use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TenantDataCostPolicy {
    pub tenant_id: String,
    pub daily_ingest_bytes_budget: i64,
    pub hot_storage_bytes_budget: i64,
    pub warm_storage_bytes_budget: i64,
    pub cold_storage_bytes_budget: i64,
    pub sampling_enabled: bool,
    pub low_value_sampling_percent: i32,
    pub high_value_sampling_percent: i32,
    pub drop_low_value_when_over_budget: bool,
    pub schema_drop_rules: serde_json::Value,
    pub source_budgets: serde_json::Value,
    pub integration_budgets: serde_json::Value,
    pub team_budgets: serde_json::Value,
    pub updated_at: DateTime<Utc>,
}

impl TenantDataCostPolicy {
    pub fn default_for_tenant(tenant_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            daily_ingest_bytes_budget: 25_000_000_000,
            hot_storage_bytes_budget: 10_000_000_000,
            warm_storage_bytes_budget: 10_000_000_000,
            cold_storage_bytes_budget: 5_000_000_000,
            sampling_enabled: true,
            low_value_sampling_percent: 25,
            high_value_sampling_percent: 100,
            drop_low_value_when_over_budget: true,
            schema_drop_rules: serde_json::json!([
                {"field": "event_type", "op": "in", "value": ["heartbeat", "metrics", "debug"]},
                {"field": "severity", "op": "==", "value": "DEBUG"},
                {"field": "message", "op": "contains", "value": "health check"}
            ]),
            source_budgets: serde_json::json!({}),
            integration_budgets: serde_json::json!({}),
            team_budgets: serde_json::json!({}),
            updated_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantCostDimensionUsage {
    pub dimension: String,
    pub key: String,
    pub bytes: u64,
    pub logs: u64,
    pub sampled: u64,
    pub dropped: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantCostDashboard {
    pub tenant_id: String,
    pub policy: TenantDataCostPolicy,
    pub usage_bytes_today: u64,
    pub usage_logs_today: u64,
    pub sampled_logs_today: u64,
    pub dropped_logs_today: u64,
    pub tenant_budget_pressure: f64,
    pub hot_storage_pressure: f64,
    pub warm_storage_pressure: f64,
    pub cold_storage_pressure: f64,
    pub top_sources: Vec<TenantCostDimensionUsage>,
    pub top_integrations: Vec<TenantCostDimensionUsage>,
    pub top_teams: Vec<TenantCostDimensionUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantDataCostPolicyUpdate {
    pub daily_ingest_bytes_budget: Option<i64>,
    pub hot_storage_bytes_budget: Option<i64>,
    pub warm_storage_bytes_budget: Option<i64>,
    pub cold_storage_bytes_budget: Option<i64>,
    pub sampling_enabled: Option<bool>,
    pub low_value_sampling_percent: Option<i32>,
    pub high_value_sampling_percent: Option<i32>,
    pub drop_low_value_when_over_budget: Option<bool>,
    pub schema_drop_rules: Option<serde_json::Value>,
    pub source_budgets: Option<serde_json::Value>,
    pub integration_budgets: Option<serde_json::Value>,
    pub team_budgets: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostDecision {
    pub action: String,
    pub keep: bool,
    pub sampled: bool,
    pub dropped: bool,
    pub sample_rate_percent: i32,
    pub reason: String,
    pub estimated_bytes: u64,
    pub source_key: String,
    pub integration_key: String,
    pub team_key: String,
}