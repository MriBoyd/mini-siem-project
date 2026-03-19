use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, Serialize, Deserialize, Clone, FromRow)]
pub struct DetectionRule {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub rule_type: String,
    pub severity: String,
    pub threshold: Option<i32>,
    pub window_seconds: Option<i32>,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct RuleCreate {
    pub name: String,
    pub description: Option<String>,
    pub rule_type: String,
    pub severity: String,
    pub threshold: Option<i32>,
    pub window_seconds: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct RuleUpdate {
    pub name: Option<String>,
    pub description: Option<String>,
    pub severity: Option<String>,
    pub threshold: Option<i32>,
    pub window_seconds: Option<i32>,
    pub is_enabled: Option<bool>,
}
