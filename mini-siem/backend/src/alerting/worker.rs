use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::sync::{mpsc, broadcast};
use tracing::{info, error};

use crate::db::PostgresDb;
use crate::db::cache::Cache;
use crate::db::redis::RedisCache;
use crate::response::engine::ResponseEngine;
use crate::types::Alert;
use crate::queue::kafka::KafkaQueue;

/// Spawn an alert worker that consumes `siem-alerts` from Kafka, persists alerts,
/// updates Redis counters, triggers response engine actions, and broadcasts alerts.
pub async fn spawn_alert_worker(
    kafka: Arc<KafkaQueue>,
    db: Arc<PostgresDb>,
    redis: RedisCache,
    response_engine: Arc<ResponseEngine>,
    alert_tx: broadcast::Sender<Alert>,
    stats_tx: broadcast::Sender<crate::types::DashboardStats>,
    db_tx: tokio::sync::mpsc::Sender<Alert>,
    mut shutdown_rx: broadcast::Receiver<()>,
    pause_on_full: bool,
    pause_timeout_ms: u64,
) -> tokio::task::JoinHandle<()> {
    // internal channel from Kafka consumer to worker
    let (tx, mut rx) = mpsc::channel::<Alert>(1000);
    let full_counter = Arc::new(AtomicUsize::new(0));
    let kafka_consumer = kafka.clone();

    // Spawn the Kafka consumer task
    let consumer_handle = tokio::spawn(async move {
        let res = kafka_consumer.consume_alerts(tx, Some(full_counter.clone()), pause_on_full, pause_timeout_ms).await;
        if let Err(e) = res {
            error!("Kafka alert consumer error: {}", e);
        }
    });

    // Spawn the processing worker
    let handle = tokio::spawn(async move {
        info!("🔁 Alert worker started");

        loop {
            tokio::select! {
                Some(alert) = rx.recv() => {
                    info!("⬇️  Processing alert {} from Kafka", alert.id);
                    // Enqueue to DB batcher via the internal channel. If the channel is full,
                    // fallback to immediate DB write to avoid data loss.
                    if let Err(e) = db_tx.try_send(alert.clone()) {
                        error!("DB batcher channel full, falling back to immediate DB write: {}", e);
                        match db.get_open_alerts_by_ip(&alert.tenant_id, &alert.source_ip).await {
                            Ok(mut existing_alerts) => {
                                if let Some(existing) = existing_alerts.first_mut() {
                                    existing.last_seen = alert.last_seen;
                                    existing.events_count += alert.events_count;
                                    if let Err(e) = db.update_alert(existing, Some(redis.clone())).await {
                                        error!("Failed to update alert in DB: {}", e);
                                    }
                                    let _ = alert_tx.send(existing.clone());
                                } else {
                                    if let Err(e) = db.create_alert(&alert).await {
                                        error!("Failed to save alert to DB: {}", e);
                                    }
                                    let _ = alert_tx.send(alert.clone());
                                }
                            }
                            Err(e) => {
                                error!("Failed to query existing alerts: {}", e);
                                // fallback to create
                                if let Err(e) = db.create_alert(&alert).await {
                                    error!("Failed to save alert to DB (fallback): {}", e);
                                }
                                let _ = alert_tx.send(alert.clone());
                            }
                        }
                    }

                    // Trigger response engine (SOAR) asynchronously
                    let re = response_engine.clone();
                    let alert_clone = alert.clone();
                    tokio::spawn(async move {
                        re.handle_alert(&alert_clone).await;
                    });

                    // Update per-tenant alert counters for dashboard isolation.
                    let is_crit = alert.severity == crate::types::AlertSeverity::Critical;
                    let tenant_prefix = format!("siem:tenant:{}:stats", alert.tenant_id);
                    let total_alerts_key = format!("{}:total_alerts", tenant_prefix);
                    let active_alerts_key = format!("{}:active_alerts", tenant_prefix);
                    let critical_alerts_key = format!("{}:critical_alerts", tenant_prefix);
                    let total_logs_key = format!("{}:total_logs", tenant_prefix);

                    let ta = redis.increment_counter(&total_alerts_key, 86400).await.ok();
                    let aa = redis.increment_counter(&active_alerts_key, 86400).await.ok();
                    if is_crit {
                        let _ = redis.increment_counter(&critical_alerts_key, 86400).await;
                    }

                    if let (Some(ta), Some(aa), Some(tl)) = (ta, aa, redis.get_counter(&total_logs_key).await.ok().flatten()) {
                        let ca = redis.get_counter(&critical_alerts_key).await.ok().flatten().unwrap_or(0);
                        let stats = crate::types::DashboardStats {
                            tenant_id: alert.tenant_id.clone(),
                            total_logs: tl as i64,
                            total_alerts: ta as i64,
                            active_alerts: aa as i64,
                            critical_alerts: ca as i64,
                        };
                        let _ = stats_tx.send(stats);
                        let _ = db.save_stats(&alert.tenant_id, tl as i64, ta as i64, aa as i64, ca as i64).await;
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("🛑 Alert worker received shutdown");
                    break;
                }
            }
        }

        // ensure consumer task is stopped
        consumer_handle.abort();
        info!("🔁 Alert worker stopped");
    });

    handle
}
