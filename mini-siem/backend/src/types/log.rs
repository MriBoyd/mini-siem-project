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

#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn create_test_log(event_type: &str, message: &str) -> Log {
        let now = Utc::now();
        Log {
            id: Uuid::new_v4(),
            timestamp: now,
            event_type: event_type.to_string(),
            source_ip: "127.0.0.1".to_string(),
            target_user: None,
            service: None,
            message: message.to_string(),
            severity: LogSeverity::Info,
            metadata: serde_json::Value::Null,
            received_at: now,
        }
    }

    #[test]
    fn test_is_failed_login() {
        let log1 = create_test_log("login_failed", "Failed to login");
        assert!(log1.is_failed_login());

        let log2 = create_test_log("system", "Failed password for root from 192.168.1.1 port 22 ssh2");
        assert!(log2.is_failed_login());

        let log3 = create_test_log("auth", "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.1");
        assert!(log3.is_failed_login());

        let log4 = create_test_log("system", "Some other message");
        assert!(!log4.is_failed_login());
    }

    #[test]
    fn test_is_successful_login() {
        let log1 = create_test_log("login_success", "User root logged in");
        assert!(log1.is_successful_login());

        let log2 = create_test_log("ssh", "Accepted password for root from 192.168.1.1 port 22 ssh2");
        assert!(log2.is_successful_login());

        let log3 = create_test_log("system", "Some other message");
        assert!(!log3.is_successful_login());
    }
}
