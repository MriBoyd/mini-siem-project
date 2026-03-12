use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub source_ip: String,
    pub target_user: Option<String>,
    pub service: Option<String>,
    pub message: String,
    pub severity: LogSeverity,
    pub metadata: serde_json::Value,
    pub received_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
    Debug,
}

impl fmt::Display for LogSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogSeverity::Critical => write!(f, "CRITICAL"),
            LogSeverity::High => write!(f, "HIGH"),
            LogSeverity::Medium => write!(f, "MEDIUM"),
            LogSeverity::Low => write!(f, "LOW"),
            LogSeverity::Info => write!(f, "INFO"),
            LogSeverity::Debug => write!(f, "DEBUG"),
        }
    }
}

impl Log {
    pub fn new(
        event_type: String,
        source_ip: String,
        message: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            timestamp: now,
            event_type,
            source_ip,
            target_user: None,
            service: None,
            message,
            severity: LogSeverity::Info,
            metadata: serde_json::Value::Null,
            received_at: now,
        }
    }
    
    pub fn is_failed_login(&self) -> bool {
        self.event_type.contains("login_failed") || 
        self.message.contains("Failed password") ||
        self.message.contains("authentication failure")
    }
    
    pub fn is_successful_login(&self) -> bool {
        self.event_type.contains("login_success") ||
        self.message.contains("Accepted password")
    }
}