use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditEvent {
    pub id: uuid::Uuid,
    pub tenant_id: String,
    pub actor_user_id: String,
    pub actor_email: String,
    pub actor_roles: Vec<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub target_tenant_id: Option<String>,
    pub request_id: Option<String>,
    pub metadata: serde_json::Value,
    pub previous_hash: Option<String>,
    pub event_hash: String,
    pub signature: String,
    pub created_at: DateTime<Utc>,
}