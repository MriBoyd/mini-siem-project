use actix_web::{post, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{Utc, DateTime};
use tracing::{info, warn};

use crate::api::server::AppState;
use crate::types::{Log, LogSeverity};
use tokio::sync::mpsc::error::TrySendError;

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
    
    // Persist into the database (logs table)
    if let Err(e) = state.db.create_log(&log).await {
        warn!("Failed to persist log: {}", e);
    }

    // Try to enqueue into in-memory queue for downstream processing. If the queue
    // is full, return `429 Too Many Requests` to signal backpressure.
    match state.log_tx.try_send(log.clone()) {
        Ok(_) => {
            // Also attempt to send to Kafka in background (best-effort)
            let kafka = state.kafka.clone();
            let l = log.clone();
            actix_web::rt::spawn(async move {
                if let Err(e) = kafka.send_log(&l).await {
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

        if let Err(e) = state.db.create_log(&log).await {
            warn!("Failed to persist log: {}", e);
        }

        match state.log_tx.try_send(log.clone()) {
            Ok(_) => {
                let kafka = state.kafka.clone();
                let l = log.clone();
                actix_web::rt::spawn(async move {
                    if let Err(e) = kafka.send_log(&l).await {
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
    HttpResponse::Accepted().json(responses)
}