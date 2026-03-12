use actix_web::{post, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{Utc, DateTime};
use tracing::{info, warn};

use crate::types::{Log, LogSeverity, Result};

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
    
    // TODO: Send to queue for processing
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
) -> impl Responder {
    let now = Utc::now();
    let mut responses = Vec::with_capacity(req.logs.len());
    
    for log_req in &req.logs {
        let log_id = Uuid::new_v4();
        responses.push(IngestLogResponse {
            id: log_id.to_string(),
            status: "accepted".to_string(),
            accepted_at: now,
        });
    }
    
    info!("📦 Accepted batch of {} logs", responses.len());
    HttpResponse::Accepted().json(responses)
}