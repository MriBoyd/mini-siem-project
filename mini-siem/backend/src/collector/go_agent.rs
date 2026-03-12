use actix_web::{post, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{Utc, DateTime, NaiveDateTime};
use tracing::{info, warn};

use crate::types::{Log, LogSeverity};
use crate::queue::kafka::KafkaQueue;

// Match the Go agent's log format
#[derive(Debug, Deserialize)]
pub struct GoAgentLog {
    pub timestamp: Option<String>,
    pub source: String,
    pub host: Option<String>,
    pub file: Option<String>,
    pub message: String,
    pub source_type: String,
    pub tags: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct GoAgentBatch {
    pub logs: Vec<GoAgentLog>,
}

#[post("/api/v1/logs/ingest")]
pub async fn ingest_from_go_agent(
    req: web::Json<GoAgentLog>,
    kafka: web::Data<KafkaQueue>,
) -> impl Responder {
    let log_id = Uuid::new_v4();
    let now = Utc::now();
    
    // Parse timestamp if provided
    let timestamp = match &req.timestamp {
        Some(ts) => {
            DateTime::parse_from_rfc3339(ts)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or(now)
        }
        None => now,
    };
    
    // Determine event type from message or tags
    let event_type = req.tags
        .as_ref()
        .and_then(|t| t.get("event_type"))
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    
    // Create log
    let log = Log {
        id: log_id,
        timestamp,
        event_type,
        source_ip: req.host.clone().unwrap_or_else(|| "0.0.0.0".to_string()),
        target_user: None,
        service: req.tags.as_ref().and_then(|t| t.get("service")).cloned(),
        message: req.message.clone(),
        severity: LogSeverity::Info,
        metadata: serde_json::json!({
            "source": req.source,
            "file": req.file,
            "source_type": req.source_type,
            "tags": req.tags,
        }),
        received_at: now,
    };
    
    // Send to Kafka
    match kafka.send_log(&log).await {
        Ok(_) => {
            info!("📥 Log from Go agent: {} from {}", log_id, log.source_ip);
            HttpResponse::Accepted().json(serde_json::json!({
                "id": log_id.to_string(),
                "status": "accepted"
            }))
        }
        Err(e) => {
            warn!("Failed to send log to Kafka: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to process log"
            }))
        }
    }
}

#[post("/api/v1/logs/batch")]
pub async fn ingest_batch_from_go_agent(
    req: web::Json<GoAgentBatch>,
    kafka: web::Data<KafkaQueue>,
) -> impl Responder {
    let now = Utc::now();
    let mut success_count = 0;
    
    for agent_log in &req.logs {
        let log_id = Uuid::new_v4();
        
        let timestamp = match &agent_log.timestamp {
            Some(ts) => {
                DateTime::parse_from_rfc3339(ts)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or(now)
            }
            None => now,
        };
        
        let log = Log {
            id: log_id,
            timestamp,
            event_type: "unknown".to_string(),
            source_ip: agent_log.host.clone().unwrap_or_else(|| "0.0.0.0".to_string()),
            target_user: None,
            service: None,
            message: agent_log.message.clone(),
            severity: LogSeverity::Info,
            metadata: serde_json::json!({
                "source": agent_log.source,
                "file": agent_log.file,
                "source_type": agent_log.source_type,
                "tags": agent_log.tags,
            }),
            received_at: now,
        };
        
        match kafka.send_log(&log).await {
            Ok(_) => success_count += 1,
            Err(e) => warn!("Failed to send batch log: {}", e),
        }
    }
    
    info!("📦 Batch from Go agent: {}/{} accepted", success_count, req.logs.len());
    
    HttpResponse::Accepted().json(serde_json::json!({
        "accepted": success_count,
        "total": req.logs.len()
    }))
}