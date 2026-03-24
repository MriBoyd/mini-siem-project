use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcsLog {
    // Core fields
    #[serde(rename = "@timestamp")]
    pub timestamp: DateTime<Utc>,
    #[serde(rename = "log.level")]
    pub log_level: Option<String>,
    pub message: Option<String>,
    #[serde(rename = "event.kind")]
    pub event_kind: Option<String>,
    #[serde(rename = "event.category")]
    pub event_category: Vec<String>,
    #[serde(rename = "event.type")]
    pub event_type: Vec<String>,
    #[serde(rename = "event.outcome")]
    pub event_outcome: Option<String>,

    // Source/Destination
    #[serde(rename = "source.ip")]
    pub source_ip: Option<String>,
    #[serde(rename = "source.port")]
    pub source_port: Option<u16>,
    #[serde(rename = "destination.ip")]
    pub destination_ip: Option<String>,
    #[serde(rename = "destination.port")]
    pub destination_port: Option<u16>,

    // User
    #[serde(rename = "user.name")]
    pub user_name: Option<String>,
    #[serde(rename = "user.id")]
    pub user_id: Option<String>,

    // Host
    #[serde(rename = "host.name")]
    pub host_name: Option<String>,
    #[serde(rename = "host.ip")]
    pub host_ip: Vec<String>,

    // Process
    #[serde(rename = "process.name")]
    pub process_name: Option<String>,
    #[serde(rename = "process.pid")]
    pub process_pid: Option<u64>,
    #[serde(rename = "process.executable")]
    pub process_executable: Option<String>,
    #[serde(rename = "process.args")]
    pub process_args: Vec<String>,

    // Custom/Extracted metadata
    pub labels: HashMap<String, String>,
    pub tags: Vec<String>,
    
    // Original log reference
    #[serde(rename = "event.original")]
    pub event_original: Option<String>,
    #[serde(rename = "event.id")]
    pub event_id: Uuid,
}

impl EcsLog {
    pub fn new() -> Self {
        Self {
            timestamp: Utc::now(),
            log_level: None,
            message: None,
            event_kind: None,
            event_category: Vec::new(),
            event_type: Vec::new(),
            event_outcome: None,
            source_ip: None,
            source_port: None,
            destination_ip: None,
            destination_port: None,
            user_name: None,
            user_id: None,
            host_name: None,
            host_ip: Vec::new(),
            process_name: None,
            process_pid: None,
            process_executable: None,
            process_args: Vec::new(),
            labels: HashMap::new(),
            tags: Vec::new(),
            event_original: None,
            event_id: Uuid::new_v4(),
        }
    }
}
