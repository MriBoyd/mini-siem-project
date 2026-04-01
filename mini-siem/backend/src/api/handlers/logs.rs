use actix_web::{post, web, HttpResponse, Responder, HttpRequest, HttpMessage};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{Utc, DateTime};
use tracing::info;
use tokio::time::{timeout, Duration};

use crate::api::server::AppState;
use crate::db::cache::Cache;
use crate::auth::jwt::Claims;
use crate::types::{Log, LogSeverity};
use serde_json::Value;

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
    req_head: HttpRequest,
    req: web::Json<IngestLogRequest>,
    state: web::Data<AppState>,
) -> impl Responder {
    let claims = match req_head.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().body("missing auth"),
    };

    let log_id = Uuid::new_v4();
    let now = Utc::now();
    
    // Create log object
    let log = Log {
        id: log_id,
        tenant_id: claims.tenant_id.clone(),
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

    // Canonical ingest path: enqueue to the shared producer task.
    // The task owns Kafka send I/O so request handlers avoid per-request spawn/
    // send overhead and fail fast when the bounded queue is saturated.
    if let Err(response) = enqueue_ingest_log(&state, log).await {
        return response;
    }

    info!("📥 Received log {} from {}", log_id, req.source_ip);
    
    // Update Redis counter for total logs and publish aggregated stats (best-effort)
    let tenant_prefix = format!("siem:tenant:{}:stats", claims.tenant_id);
    if let Ok(_) = state.redis.increment_counter(&format!("{}:total_logs", tenant_prefix), 86400).await {
        // Try to read counters from Redis (L1 cache will be used if available)
        let total_logs: Option<u32> = state.redis.get_counter(&format!("{}:total_logs", tenant_prefix)).await.ok().flatten();
        let total_alerts: Option<u32> = state.redis.get_counter(&format!("{}:total_alerts", tenant_prefix)).await.ok().flatten();
        let active_alerts: Option<u32> = state.redis.get_counter(&format!("{}:active_alerts", tenant_prefix)).await.ok().flatten();
        let critical_alerts: Option<u32> = state.redis.get_counter(&format!("{}:critical_alerts", tenant_prefix)).await.ok().flatten();

        if let (Some(tl), Some(ta), Some(aa), Some(ca)) = (total_logs, total_alerts, active_alerts, critical_alerts) {
            let stats = crate::types::DashboardStats {
                tenant_id: claims.tenant_id.clone(),
                total_logs: tl as i64,
                total_alerts: ta as i64,
                active_alerts: aa as i64,
                critical_alerts: ca as i64,
            };
            let _ = state.stats_tx.send(stats);
            let _ = state.db.save_stats(&claims.tenant_id, tl as i64, ta as i64, aa as i64, ca as i64).await;
        } else {
            // Fallback: compute from DB and seed Redis
            if let Ok((tl, ta, aa, ca)) = state.db.get_stats(&claims.tenant_id).await {
                let stats = crate::types::DashboardStats::from((tl, ta, aa, ca));
                let _ = state.stats_tx.send(stats.clone());
                // Seed Redis counters (best-effort)
                let _ = state.redis.set_counter(&format!("{}:total_logs", tenant_prefix), tl as u64, Some(86400)).await;
                let _ = state.redis.set_counter(&format!("{}:total_alerts", tenant_prefix), ta as u64, Some(86400)).await;
                let _ = state.redis.set_counter(&format!("{}:active_alerts", tenant_prefix), aa as u64, Some(86400)).await;
                let _ = state.redis.set_counter(&format!("{}:critical_alerts", tenant_prefix), ca as u64, Some(86400)).await;
                let _ = state.db.save_stats(&claims.tenant_id, tl, ta, aa, ca).await;
            }
        }
    }

    HttpResponse::Accepted().json(IngestLogResponse {
        id: log_id.to_string(),
        status: "accepted".to_string(),
        accepted_at: now,
    })
}

#[actix_web::get("/api/v1/logs/recent")]
pub async fn recent_logs(req_head: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    // Return recent logs from Elasticsearch for UI compatibility.
    let claims = match req_head.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().body("missing auth"),
    };

    if let Some(el) = state.elastic.borrow().clone() {
        let index_name = std::env::var("ELASTICSEARCH_INDEX").unwrap_or_else(|_| "mini-siem-logs".to_string());
        let query = serde_json::json!({ "term": { "tenant_id": claims.tenant_id } });
        match el.as_ref().search(&index_name, query, 0, 50).await {
            Ok(v) => {
                // extract hits -> _source using JSON pointer
                let mut res: Vec<Value> = Vec::new();
                if let Some(hits_arr) = v.pointer("/hits/hits").and_then(|p| p.as_array()) {
                    for item in hits_arr.iter() {
                        if let Some(src) = item.get("_source") {
                            res.push(src.clone());
                        }
                    }
                }
                return HttpResponse::Ok().json(res);
            }
            Err(e) => {
                tracing::error!("elasticsearch search error: {}", e);
                HttpResponse::ServiceUnavailable().body("elasticsearch unavailable")
            }
        }
    } else {
        HttpResponse::ServiceUnavailable().body("elasticsearch not configured")
    }
}

#[derive(Debug, Deserialize)]
pub struct BatchIngestRequest {
    pub logs: Vec<IngestLogRequest>,
}

#[post("/api/v1/logs/batch")]
pub async fn ingest_batch(
    req_head: HttpRequest,
    req: web::Json<BatchIngestRequest>,
    state: web::Data<AppState>,
) -> impl Responder {
    let claims = match req_head.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().body("missing auth"),
    };

    let now = Utc::now();
    let mut responses = Vec::with_capacity(req.logs.len());
    
    for log_req in &req.logs {
        let log_id = Uuid::new_v4();
        let log = Log {
            id: log_id,
            tenant_id: claims.tenant_id.clone(),
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

        // Canonical ingest path: enqueue each log to the shared producer task.
        if let Err(response) = enqueue_ingest_log(&state, log).await {
            return response;
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
        let _ = state.redis.incr_by(&format!("siem:tenant:{}:stats:total_logs", claims.tenant_id), responses.len() as u64, 86400).await;
    }

    // Try to read counters from Redis
    let tenant_prefix = format!("siem:tenant:{}:stats", claims.tenant_id);
    let total_logs: Option<u32> = state.redis.get_counter(&format!("{}:total_logs", tenant_prefix)).await.ok().flatten();
    let total_alerts: Option<u32> = state.redis.get_counter(&format!("{}:total_alerts", tenant_prefix)).await.ok().flatten();
    let active_alerts: Option<u32> = state.redis.get_counter(&format!("{}:active_alerts", tenant_prefix)).await.ok().flatten();
    let critical_alerts: Option<u32> = state.redis.get_counter(&format!("{}:critical_alerts", tenant_prefix)).await.ok().flatten();

    if let (Some(tl), Some(ta), Some(aa), Some(ca)) = (total_logs, total_alerts, active_alerts, critical_alerts) {
        let stats = crate::types::DashboardStats {
            tenant_id: claims.tenant_id.clone(),
            total_logs: tl as i64,
            total_alerts: ta as i64,
            active_alerts: aa as i64,
            critical_alerts: ca as i64,
        };
        let _ = state.stats_tx.send(stats);
        let _ = state.db.save_stats(&claims.tenant_id, tl as i64, ta as i64, aa as i64, ca as i64).await;
    } else if let Ok((tl, ta, aa, ca)) = state.db.get_stats(&claims.tenant_id).await {
        let stats = crate::types::DashboardStats::from((tl, ta, aa, ca));
        let _ = state.stats_tx.send(stats.clone());
        // Seed Redis (best-effort)
        let _ = state.redis.set_counter(&format!("{}:total_logs", tenant_prefix), tl as u64, Some(86400)).await;
        let _ = state.redis.set_counter(&format!("{}:total_alerts", tenant_prefix), ta as u64, Some(86400)).await;
        let _ = state.redis.set_counter(&format!("{}:active_alerts", tenant_prefix), aa as u64, Some(86400)).await;
        let _ = state.redis.set_counter(&format!("{}:critical_alerts", tenant_prefix), ca as u64, Some(86400)).await;
        let _ = state.db.save_stats(&claims.tenant_id, tl, ta, aa, ca).await;
    }
    HttpResponse::Accepted().json(responses)
}

async fn enqueue_ingest_log(state: &web::Data<AppState>, log: Log) -> Result<(), HttpResponse> {
    let send_fut = state.ingest_tx.send(std::sync::Arc::new(log));
    match timeout(Duration::from_millis(25), send_fut).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => {
            tracing::error!("ingest queue closed");
            Err(HttpResponse::ServiceUnavailable().body("ingest unavailable"))
        }
        Err(_) => {
            tracing::warn!("ingest queue saturated, timing out enqueue");
            Err(HttpResponse::ServiceUnavailable().body("ingest backlog"))
        }
    }
}