use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TenantCompliancePolicy {
    pub tenant_id: String,
    pub retention_days: i32,
    pub legal_hold: bool,
    pub legal_hold_reason: Option<String>,
    pub legal_hold_until: Option<DateTime<Utc>>,
    pub access_review_interval_days: i32,
    pub key_rotation_interval_days: i32,
    pub last_key_rotation_at: Option<DateTime<Utc>>,
    pub evidence_export_enabled: bool,
    pub updated_at: DateTime<Utc>,
}

impl TenantCompliancePolicy {
    pub fn default_for_tenant(tenant_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            retention_days: 365,
            legal_hold: false,
            legal_hold_reason: None,
            legal_hold_until: None,
            access_review_interval_days: 90,
            key_rotation_interval_days: 90,
            last_key_rotation_at: None,
            evidence_export_enabled: true,
            updated_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessReviewUser {
    pub id: uuid::Uuid,
    pub tenant_id: String,
    pub email: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceEvidenceBundle {
    pub tenant_id: String,
    pub generated_at: DateTime<Utc>,
    pub policy: TenantCompliancePolicy,
    pub access_review: serde_json::Value,
    pub audit_summary: serde_json::Value,
    pub retention_summary: serde_json::Value,
}