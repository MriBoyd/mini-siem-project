use std::sync::Arc;
use tokio::sync::{mpsc, broadcast};
use tracing::{info, error};

use crate::db::PostgresDb;
use crate::types::Alert;

/// Spawn a DB batcher that collects alerts and performs batched writes.
/// - Flushes when `batch_size` reached or `flush_interval_ms` elapsed.
pub fn spawn_db_batcher(
    db: Arc<PostgresDb>,
    mut rx: mpsc::Receiver<Alert>,
    mut shutdown_rx: broadcast::Receiver<()>,
    batch_size: usize,
    flush_interval_ms: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        info!("🗄️  DB batcher started (batch_size={}, flush_ms={})", batch_size, flush_interval_ms);

        let mut buffer: Vec<Alert> = Vec::with_capacity(batch_size);
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(flush_interval_ms));

        loop {
            tokio::select! {
                Some(alert) = rx.recv() => {
                    buffer.push(alert);
                    if buffer.len() >= batch_size {
                        if let Err(e) = flush_batch(&db, &mut buffer).await {
                            error!("Failed to flush alert batch: {}", e);
                        }
                    }
                }
                _ = interval.tick() => {
                    if !buffer.is_empty() {
                        if let Err(e) = flush_batch(&db, &mut buffer).await {
                            error!("Failed to flush alert batch: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("🛑 DB batcher received shutdown, flushing {} alerts", buffer.len());
                    if !buffer.is_empty() {
                        if let Err(e) = flush_batch(&db, &mut buffer).await {
                            error!("Failed to flush alert batch at shutdown: {}", e);
                        }
                    }
                    break;
                }
            }
        }

        info!("🗄️  DB batcher stopped");
    })
}

async fn flush_batch(db: &PostgresDb, buffer: &mut Vec<Alert>) -> anyhow::Result<()> {
    if buffer.is_empty() { return Ok(()); }

    use std::collections::HashMap;
    let mut by_tenant: HashMap<String, Vec<Alert>> = HashMap::new();
    for alert in buffer.drain(..) {
        by_tenant.entry(alert.tenant_id.clone()).or_default().push(alert);
    }

    for (tenant_id, tenant_alerts) in by_tenant.into_iter() {
        let ips: Vec<String> = tenant_alerts.iter().map(|a| a.source_ip.clone()).collect();
        let unique_ips: Vec<String> = {
            let mut s = ips.clone();
            s.sort(); s.dedup();
            s
        };

        let existing = db.get_open_alerts_by_ips(&tenant_id, &unique_ips).await.unwrap_or_default();

        let mut existing_map: HashMap<String, Alert> = HashMap::new();
        for e in existing.into_iter() {
            existing_map.entry(e.source_ip.clone()).or_insert(e);
        }

        let mut to_update: Vec<Alert> = Vec::new();
        let mut to_create: Vec<Alert> = Vec::new();

        for alert in tenant_alerts {
            if let Some(mut ex) = existing_map.get_mut(&alert.source_ip).cloned() {
                ex.last_seen = alert.last_seen.max(ex.last_seen);
                ex.events_count = ex.events_count + alert.events_count;
                ex.events.extend(alert.events);
                to_update.push(ex);
            } else {
                to_create.push(alert);
            }
        }

        if !to_create.is_empty() {
            db.create_alerts_batch(&to_create).await?;
        }

        if !to_update.is_empty() {
            if let Err(e) = db.upsert_alerts_batch(&to_update).await {
                error!("Failed to upsert alert batch: {}", e);
            }
        }
    }

    Ok(())
}
