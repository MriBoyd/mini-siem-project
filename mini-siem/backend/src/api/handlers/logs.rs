use actix_web::{post, web, HttpResponse, Responder, HttpRequest, HttpMessage};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{Utc, DateTime};
use tracing::info;
use tokio::time::{timeout, Duration};

use crate::api::server::AppState;
use crate::api::tenant::enforce_tenant_fixed_window;
use crate::costs::{evaluate_cost_decision, record_cost_usage};
use crate::monitoring::bounded_tenant_label;
use crate::db::cache::Cache;
use crate::auth::jwt::Claims;
use crate::types::{Log, LogSeverity};
use serde_json::Value;
use tracing::Span;

#[derive(Debug, Deserialize)]
pub struct IngestLogRequest {
    pub event_type: String,
    pub source_ip: String,
    pub target_user: Option<String>,
    pub service: Option<String>,
    pub message: String,
    pub severity: Option<LogSeverity>,
    pub timestamp: Option<DateTime<Utc>>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct IngestLogResponse {
    pub id: String,
    pub status: String,
    pub accepted_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_reason: Option<String>,
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
    let tenant_label = bounded_tenant_label(&claims.tenant_id);
    Span::current().record("tenant_id", tracing::field::display(&tenant_label));

    if let Err(response) = enforce_tenant_fixed_window(
        &state,
        &claims.tenant_id,
        "ingest_events",
        state.tenant_limits.ingest_events_per_minute,
        1,
    ).await {
        return response;
    }
    
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
        metadata: req.metadata.clone().unwrap_or(serde_json::Value::Null),
        received_at: now,
    };

    let decision = match evaluate_cost_decision(&state, &claims.tenant_id, &req).await {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!("cost controller failed, defaulting to keep: {}", e);
            (
                crate::db::models::data_cost::TenantDataCostPolicy::default_for_tenant(&claims.tenant_id),
                crate::db::models::data_cost::CostDecision {
                    action: "keep".to_string(),
                    keep: true,
                    sampled: false,
                    dropped: false,
                    sample_rate_percent: 100,
                    reason: "cost controller unavailable".to_string(),
                    estimated_bytes: 0,
                    source_key: req.source_ip.clone(),
                    integration_key: req.service.clone().unwrap_or_else(|| req.event_type.clone()),
                    team_key: "unassigned".to_string(),
                },
            ).1
        }
    };

    if let Err(e) = record_cost_usage(&state, &claims.tenant_id, &decision).await {
        tracing::warn!("failed to record cost usage: {}", e);
    }

    if !decision.keep {
        info!("📉 Dropped sampled log {} for cost control: {}", log_id, decision.reason);
        metrics::counter!("siem_cost_logs_dropped_total", 1, "tenant" => tenant_label.clone(), "action" => decision.action.clone());
        return HttpResponse::Accepted().json(IngestLogResponse {
            id: log_id.to_string(),
            status: decision.action.clone(),
            accepted_at: now,
            cost_action: Some(decision.action),
            cost_reason: Some(decision.reason),
        });
    }
    
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
    let heartbeat = Utc::now().timestamp().to_string();
    let _ = state.redis.set_string("siem:health:agent_last_seen", &heartbeat, Some(300)).await;
    let _ = state.redis.set_string("siem:health:ingest_last_seen", &heartbeat, Some(300)).await;
    metrics::counter!("siem_tenant_ingest_logs_total", 1, "tenant" => tenant_label.clone(), "kind" => "single");
    metrics::counter!("siem_http_ingest_requests_total", 1, "kind" => "single", "status_class" => "2xx");
    
    // Hot path stays write-only: the background stats task reads Redis and
    // persists/broadcasts snapshots out of band.
    let tenant_prefix = format!("siem:tenant:{}:stats", claims.tenant_id);
    if let Err(e) = state.redis.increment_counter(&format!("{}:total_logs", tenant_prefix), 86400).await {
        tracing::warn!("failed to increment tenant log counter: {}", e);
    }

    HttpResponse::Accepted().json(IngestLogResponse {
        id: log_id.to_string(),
        status: "accepted".to_string(),
        accepted_at: now,
        cost_action: Some(decision.action),
        cost_reason: Some(decision.reason),
    })
}

#[actix_web::get("/api/v1/logs/recent")]
pub async fn recent_logs(req_head: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    // Return recent logs from Elasticsearch for UI compatibility.
    let claims = match req_head.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().body("missing auth"),
    };
    let tenant_label = bounded_tenant_label(&claims.tenant_id);
    Span::current().record("tenant_id", tracing::field::display(&tenant_label));

    if let Err(response) = enforce_tenant_fixed_window(
        &state,
        &claims.tenant_id,
        "api_requests",
        state.tenant_limits.api_requests_per_minute,
        1,
    ).await {
        return response;
    }

    if let Some(el) = state.elastic.borrow().clone() {
        let index_name = state.elastic_index.clone();
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
    let tenant_label = bounded_tenant_label(&claims.tenant_id);
    Span::current().record("tenant_id", tracing::field::display(&tenant_label));

    if let Err(response) = enforce_tenant_fixed_window(
        &state,
        &claims.tenant_id,
        "ingest_events",
        state.tenant_limits.ingest_events_per_minute,
        req.logs.len().max(1),
    ).await {
        return response;
    }

    let now = Utc::now();
    let mut responses = Vec::with_capacity(req.logs.len());
    
    for log_req in &req.logs {
        let log_id = Uuid::new_v4();
        let decision = match evaluate_cost_decision(&state, &claims.tenant_id, log_req).await {
            Ok((_, decision)) => decision,
            Err(e) => {
                tracing::warn!("cost controller failed for batch item, defaulting to keep: {}", e);
                crate::db::models::data_cost::CostDecision {
                    action: "keep".to_string(),
                    keep: true,
                    sampled: false,
                    dropped: false,
                    sample_rate_percent: 100,
                    reason: "cost controller unavailable".to_string(),
                    estimated_bytes: 0,
                    source_key: log_req.source_ip.clone(),
                    integration_key: log_req.service.clone().unwrap_or_else(|| log_req.event_type.clone()),
                    team_key: "unassigned".to_string(),
                }
            }
        };

        if let Err(e) = record_cost_usage(&state, &claims.tenant_id, &decision).await {
            tracing::warn!("failed to record cost usage for batch item: {}", e);
        }

        if !decision.keep {
            responses.push(IngestLogResponse {
                id: log_id.to_string(),
                status: decision.action.clone(),
                accepted_at: now,
                cost_action: Some(decision.action),
                cost_reason: Some(decision.reason),
            });
            continue;
        }

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
            metadata: log_req.metadata.clone().unwrap_or(serde_json::Value::Null),
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
            cost_action: Some(decision.action),
            cost_reason: Some(decision.reason),
        });
    }
    
    info!("📦 Accepted batch of {} logs", responses.len());
    let heartbeat = Utc::now().timestamp().to_string();
    let _ = state.redis.set_string("siem:health:agent_last_seen", &heartbeat, Some(300)).await;
    let _ = state.redis.set_string("siem:health:ingest_last_seen", &heartbeat, Some(300)).await;
    metrics::counter!("siem_tenant_ingest_logs_total", responses.len() as u64, "tenant" => tenant_label.clone(), "kind" => "batch");
    metrics::counter!("siem_http_ingest_requests_total", 1, "kind" => "batch", "status_class" => "2xx");
    // Hot path stays write-only; background aggregation handles snapshots.
    if responses.len() > 0 {
        let tenant_prefix = format!("siem:tenant:{}:stats", claims.tenant_id);
        if let Err(e) = state.redis.incr_by(&format!("{}:total_logs", tenant_prefix), responses.len() as u64, 86400).await {
            tracing::warn!("failed to increment tenant log counter: {}", e);
        }
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