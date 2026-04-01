use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReliabilitySloSnapshot {
    pub ingest_availability_target_percent: f64,
    pub ingest_availability_observed_percent: f64,
    pub detection_latency_target_p95_ms: f64,
    pub detection_latency_p95_ms: f64,
    pub detection_latency_p99_ms: f64,
    pub alert_delivery_latency_target_p95_ms: f64,
    pub alert_delivery_latency_p95_ms: f64,
    pub alert_delivery_latency_p99_ms: f64,
    pub sample_count: u64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ReliabilityReportRecord {
    pub id: Uuid,
    pub tenant_id: String,
    pub report_type: String,
    pub drill_name: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub duration_ms: i64,
    pub summary_json: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReliabilityReportCreate {
    pub tenant_id: String,
    pub report_type: String,
    pub drill_name: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub summary_json: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReliabilityOverview {
    pub tenant_id: String,
    pub snapshot: ReliabilitySloSnapshot,
    pub recent_reports: Vec<ReliabilityReportRecord>,
}
