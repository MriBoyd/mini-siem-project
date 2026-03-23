use actix_web::{post, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{Utc, DateTime};
use tracing::{info, warn};

use crate::api::server::AppState;
use crate::db::cache::Cache;
use crate::types::{Log, LogSeverity};
use tokio::sync::mpsc::error::TrySendError;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct IngestLogRequest {
    pub event_type: String,
    pub source_ip: String,
    pub target_user: Option<String>,
    pub service: Option<String>,
    pub message: String,
    pub severity: Option<LogSeverity>,
    pub timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct IngestLogResponse {
    pub id: String,
    pub status: String,
    pub accepted_at: DateTime<Utc>,
}

#[post("/api/v1/logs/ingest")]
pub async fn ingest_log(
    req: web::Json<IngestLogRequest>,
    state: web::Data<AppState>,
) -> impl Responder {
    let log_id = Uuid::new_v4();
    let now = Utc::now();
    
    // Create log object
    let log = Log {
        id: log_id,
        timestamp: req.timestamp.unwrap_or(now),
        event_type: req.event_type.clone(),
        source_ip: req.source_ip.clone(),
        target_user: req.target_user.clone(),
        service: req.service.clone(),
        message: req.message.clone(),
        severity: req.severity.unwrap_or(LogSeverity::Info),
        metadata: serde_json::Value::Null,
        received_at: now,
    };
    
    // Do NOT persist raw logs into Postgres here. Postgres is the source of
    // truth for alerts/config; logs are indexed in Elasticsearch via the
    // separate indexer pipeline (Kafka -> indexer -> Elasticsearch).

    // Try to enqueue into in-memory queue for downstream processing. If the queue
    // is full, return `429 Too Many Requests` to signal backpressure.
    let arc_log = Arc::new(log.clone());
    match state.log_tx.try_send(arc_log.clone()) {
        Ok(_) => {
            // Also attempt to send to Kafka in background (best-effort)
            let kafka = state.kafka.clone();
            let a = arc_log.clone();
            actix_web::rt::spawn(async move {
                if let Err(e) = kafka.send_log(&*a).await {
                    tracing::warn!("Failed to enqueue log to Kafka: {}", e);
                }
            });
        }
        Err(TrySendError::Full(_)) => {
            warn!("Log channel full - rejecting request");
            return HttpResponse::TooManyRequests().body("ingest queue full, try later");
        }
        Err(TrySendError::Closed(_)) => {
            warn!("Log channel closed - rejecting request");
            return HttpResponse::ServiceUnavailable().body("ingest service unavailable");
        }
    }

    info!("📥 Received log {} from {}", log_id, req.source_ip);
    
    // Update Redis counter for total logs and publish aggregated stats (best-effort)
    if let Ok(_) = state.redis.increment_counter("siem:stats:total_logs", 86400).await {
        // Try to read counters from Redis (L1 cache will be used if available)
        let total_logs: Option<u32> = state.redis.get_counter("siem:stats:total_logs").await.ok().flatten();
        let total_alerts: Option<u32> = state.redis.get_counter("siem:stats:total_alerts").await.ok().flatten();
        let active_alerts: Option<u32> = state.redis.get_counter("siem:stats:active_alerts").await.ok().flatten();
        let critical_alerts: Option<u32> = state.redis.get_counter("siem:stats:critical_alerts").await.ok().flatten();

        if let (Some(tl), Some(ta), Some(aa), Some(ca)) = (total_logs, total_alerts, active_alerts, critical_alerts) {
            let stats = crate::types::DashboardStats {
                total_logs: tl as i64,
                total_alerts: ta as i64,
                active_alerts: aa as i64,
                critical_alerts: ca as i64,
            };
            let _ = state.stats_tx.send(stats);
        } else {
            // Fallback: compute from DB and seed Redis
            if let Ok((tl, ta, aa, ca)) = state.db.get_stats().await {
                let stats = crate::types::DashboardStats::from((tl, ta, aa, ca));
                let _ = state.stats_tx.send(stats.clone());
                // Seed Redis counters (best-effort)
                let _ = state.redis.set_counter("siem:stats:total_logs", tl as u64, Some(86400)).await;
                let _ = state.redis.set_counter("siem:stats:total_alerts", ta as u64, Some(86400)).await;
                let _ = state.redis.set_counter("siem:stats:active_alerts", aa as u64, Some(86400)).await;
                let _ = state.redis.set_counter("siem:stats:critical_alerts", ca as u64, Some(86400)).await;
            }
        }
    }

    HttpResponse::Accepted().json(IngestLogResponse {
        id: log_id.to_string(),
        status: "accepted".to_string(),
        accepted_at: now,
    })
}

#[derive(Debug, Deserialize)]
pub struct BatchIngestRequest {
    pub logs: Vec<IngestLogRequest>,
}

#[post("/api/v1/logs/batch")]
pub async fn ingest_batch(
    req: web::Json<BatchIngestRequest>,
    state: web::Data<AppState>,
) -> impl Responder {
    let now = Utc::now();
    let mut responses = Vec::with_capacity(req.logs.len());
    
    for log_req in &req.logs {
        let log_id = Uuid::new_v4();
        let log = Log {
            id: log_id,
            timestamp: log_req.timestamp.unwrap_or(now),
            event_type: log_req.event_type.clone(),
            source_ip: log_req.source_ip.clone(),
            target_user: log_req.target_user.clone(),
            service: log_req.service.clone(),
            message: log_req.message.clone(),
            severity: log_req.severity.unwrap_or(LogSeverity::Info),
            metadata: serde_json::Value::Null,
            received_at: now,
        };

        // We intentionally do not persist raw logs to Postgres in the batch
        // ingest path. Logs are routed through Kafka and indexed into ES.
        let arc_log = Arc::new(log.clone());
        match state.log_tx.try_send(arc_log.clone()) {
            Ok(_) => {
                let kafka = state.kafka.clone();
                let a = arc_log.clone();
                actix_web::rt::spawn(async move {
                    if let Err(e) = kafka.send_log(&*a).await {
                        tracing::warn!("Failed to enqueue log to Kafka: {}", e);
                    }
                });
            }
            Err(TrySendError::Full(_)) => {
                warn!("Log channel full - rejecting batch item");
                return HttpResponse::TooManyRequests().body("ingest queue full, try later");
            }
            Err(TrySendError::Closed(_)) => {
                warn!("Log channel closed - rejecting batch item");
                return HttpResponse::ServiceUnavailable().body("ingest service unavailable");
            }
        }

        responses.push(IngestLogResponse {
            id: log_id.to_string(),
            status: "accepted".to_string(),
            accepted_at: now,
        });
    }
    
    info!("📦 Accepted batch of {} logs", responses.len());
    // Update Redis counter for total logs in one operation and publish aggregated stats (best-effort)
    if responses.len() > 0 {
        let _ = state.redis.incr_by("siem:stats:total_logs", responses.len() as u64, 86400).await;
    }

    // Try to read counters from Redis
    let total_logs: Option<u32> = state.redis.get_counter("siem:stats:total_logs").await.ok().flatten();
    let total_alerts: Option<u32> = state.redis.get_counter("siem:stats:total_alerts").await.ok().flatten();
    let active_alerts: Option<u32> = state.redis.get_counter("siem:stats:active_alerts").await.ok().flatten();
    let critical_alerts: Option<u32> = state.redis.get_counter("siem:stats:critical_alerts").await.ok().flatten();

    if let (Some(tl), Some(ta), Some(aa), Some(ca)) = (total_logs, total_alerts, active_alerts, critical_alerts) {
        let stats = crate::types::DashboardStats {
            total_logs: tl as i64,
            total_alerts: ta as i64,
            active_alerts: aa as i64,
            critical_alerts: ca as i64,
        };
        let _ = state.stats_tx.send(stats);
    } else if let Ok((tl, ta, aa, ca)) = state.db.get_stats().await {
        let stats = crate::types::DashboardStats::from((tl, ta, aa, ca));
        let _ = state.stats_tx.send(stats.clone());
        // Seed Redis (best-effort)
        let _ = state.redis.set_counter("siem:stats:total_logs", tl as u64, Some(86400)).await;
        let _ = state.redis.set_counter("siem:stats:total_alerts", ta as u64, Some(86400)).await;
        let _ = state.redis.set_counter("siem:stats:active_alerts", aa as u64, Some(86400)).await;
        let _ = state.redis.set_counter("siem:stats:critical_alerts", ca as u64, Some(86400)).await;
    }
    HttpResponse::Accepted().json(responses)
}