use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum CaseStatus {
    New,
    Investigating,
    AwaitingCustomer,
    Mitigated,
    Resolved,
    FalsePositive,
    Escalated,
    Closed,
}

impl fmt::Display for CaseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaseStatus::New => write!(f, "NEW"),
            CaseStatus::Investigating => write!(f, "INVESTIGATING"),
            CaseStatus::AwaitingCustomer => write!(f, "AWAITINGCUSTOMER"),
            CaseStatus::Mitigated => write!(f, "MITIGATED"),
            CaseStatus::Resolved => write!(f, "RESOLVED"),
            CaseStatus::FalsePositive => write!(f, "FALSEPOSITIVE"),
            CaseStatus::Escalated => write!(f, "ESCALATED"),
            CaseStatus::Closed => write!(f, "CLOSED"),
        }
    }
}

impl FromStr for CaseStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "NEW" => Ok(CaseStatus::New),
            "INVESTIGATING" => Ok(CaseStatus::Investigating),
            "AWAITINGCUSTOMER" => Ok(CaseStatus::AwaitingCustomer),
            "MITIGATED" => Ok(CaseStatus::Mitigated),
            "RESOLVED" => Ok(CaseStatus::Resolved),
            "FALSEPOSITIVE" => Ok(CaseStatus::FalsePositive),
            "ESCALATED" => Ok(CaseStatus::Escalated),
            "CLOSED" => Ok(CaseStatus::Closed),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CaseRecord {
    pub id: Uuid,
    pub tenant_id: String,
    pub primary_alert_id: Uuid,
    pub title: String,
    pub summary: String,
    pub severity: String,
    pub status: String,
    pub owner_user_id: Option<String>,
    pub owner_email: Option<String>,
    pub playbook_id: Option<Uuid>,
    pub sla_due_at: Option<DateTime<Utc>>,
    pub escalation_at: Option<DateTime<Utc>>,
    pub escalated_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub outcome: Option<String>,
    pub postmortem_summary: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CasePlaybook {
    pub id: Uuid,
    pub tenant_id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub sla_minutes: i32,
    pub escalate_after_minutes: i32,
    pub steps: serde_json::Value,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CaseTimelineEvent {
    pub id: Uuid,
    pub case_id: Uuid,
    pub tenant_id: String,
    pub event_type: String,
    pub message: String,
    pub actor_user_id: Option<String>,
    pub actor_email: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseStep {
    pub title: String,
    pub action_type: String,
    pub description: String,
    pub automated: bool,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseDetail {
    pub case_record: CaseRecord,
    pub alerts: Vec<Uuid>,
    pub timeline: Vec<CaseTimelineEvent>,
    pub playbook: Option<CasePlaybook>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCaseRequest {
    pub alert_id: Uuid,
    pub owner_user_id: Option<String>,
    pub owner_email: Option<String>,
    pub title: Option<String>,
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCaseRequest {
    pub status: Option<CaseStatus>,
    pub owner_user_id: Option<String>,
    pub owner_email: Option<String>,
    pub outcome: Option<String>,
    pub postmortem_summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddCaseEventRequest {
    pub event_type: String,
    pub message: String,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunPlaybookRequest {
    pub playbook_id: Option<Uuid>,
}