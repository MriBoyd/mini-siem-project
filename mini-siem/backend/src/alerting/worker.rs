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
    mut shutdown_rx: broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    // internal channel from Kafka consumer to worker
    let (tx, mut rx) = mpsc::channel::<Alert>(1000);
    let full_counter = Arc::new(AtomicUsize::new(0));
    let kafka_consumer = kafka.clone();

    // Spawn the Kafka consumer task
    let consumer_handle = tokio::spawn(async move {
        let res = kafka_consumer.consume_alerts(tx, Some(full_counter.clone())).await;
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

                    // Persist to DB (try update existing open alert by IP first)
                    match db.get_open_alerts_by_ip(&alert.source_ip).await {
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

                    // Trigger response engine (SOAR) asynchronously
                    let re = response_engine.clone();
                    let alert_clone = alert.clone();
                    tokio::spawn(async move {
                        re.handle_alert(&alert_clone).await;
                    });

                    // Atomically increment alert counters and fetch new values in one call
                    let is_crit = alert.severity == crate::types::AlertSeverity::Critical;
                    if let Ok((ta, aa, ca)) = redis.inc_alert_counters(is_crit, 86400).await {
                        // Try to read total_logs from L1 or DB; best-effort
                        let tl: Option<u32> = redis.get_counter("siem:stats:total_logs").await.ok().flatten();
                        if let Some(tl) = tl {
                            let stats = crate::types::DashboardStats {
                                total_logs: tl as i64,
                                total_alerts: ta as i64,
                                active_alerts: aa as i64,
                                critical_alerts: ca as i64,
                            };
                            let _ = stats_tx.send(stats);
                        } else if let Ok((otl, ota, oaa, oca)) = db.get_stats().await {
                            let stats = crate::types::DashboardStats::from((otl, ota, oaa, oca));
                            let _ = stats_tx.send(stats.clone());
                            let _ = redis.set_counter("siem:stats:total_logs", otl as u64, Some(86400)).await;
                            let _ = redis.set_counter("siem:stats:total_alerts", ota as u64, Some(86400)).await;
                            let _ = redis.set_counter("siem:stats:active_alerts", oaa as u64, Some(86400)).await;
                            let _ = redis.set_counter("siem:stats:critical_alerts", oca as u64, Some(86400)).await;
                        }
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
