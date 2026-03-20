use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::fmt;
use std::str::FromStr;

use super::Log;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: Uuid,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: AlertSeverity,
    pub description: String,
    pub source_ip: String,
    pub events: Vec<Log>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub status: AlertStatus,
    pub events_count: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "UPPERCASE")]
pub enum AlertSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlertSeverity::Critical => write!(f, "CRITICAL"),
            AlertSeverity::High => write!(f, "HIGH"),
            AlertSeverity::Medium => write!(f, "MEDIUM"),
            AlertSeverity::Low => write!(f, "LOW"),
            AlertSeverity::Info => write!(f, "INFO"),
        }
    }
}

impl FromStr for AlertSeverity {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "CRITICAL" => Ok(AlertSeverity::Critical),
            "HIGH" => Ok(AlertSeverity::High),
            "MEDIUM" => Ok(AlertSeverity::Medium),
            "LOW" => Ok(AlertSeverity::Low),
            "INFO" => Ok(AlertSeverity::Info),
            _ => Err(()),
        }
    }
}

impl fmt::Display for AlertStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlertStatus::New => write!(f, "NEW"),
            AlertStatus::Investigating => write!(f, "INVESTIGATING"),
            AlertStatus::Resolved => write!(f, "RESOLVED"),
            AlertStatus::FalsePositive => write!(f, "FALSEPOSITIVE"),
        }
    }
}

impl FromStr for AlertStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "NEW" => Ok(AlertStatus::New),
            "INVESTIGATING" => Ok(AlertStatus::Investigating),
            "RESOLVED" => Ok(AlertStatus::Resolved),
            "FALSEPOSITIVE" => Ok(AlertStatus::FalsePositive),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum AlertStatus {
    New,
    Investigating,
    Resolved,
    FalsePositive,
}

impl Alert {
    pub fn new(
        rule_id: impl Into<String>,
        rule_name: impl Into<String>,
        severity: AlertSeverity,
        description: impl Into<String>,
        source_ip: impl Into<String>,
        events: Vec<Log>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            rule_id: rule_id.into(),
            rule_name: rule_name.into(),
            severity,
            description: description.into(),
            source_ip: source_ip.into(),
            events_count: events.len(),
            events,
            first_seen: now,
            last_seen: now,
            status: AlertStatus::New,
        }
    }
}