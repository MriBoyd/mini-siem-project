use async_trait::async_trait;
use crate::types::{Log, Alert, AlertSeverity, LogTag};
use super::Rule;
use crate::detection::evaluator::RuleCondition;
use anyhow::Result;
use uuid::Uuid;

pub struct GenericRule {
    pub id: String,
    pub name: String,
    pub severity: AlertSeverity,
    pub condition: RuleCondition,
}

impl GenericRule {
    pub fn new(id: String, name: String, severity: String, condition: RuleCondition) -> Self {
        let sev = match severity.to_uppercase().as_str() {
            "CRITICAL" => AlertSeverity::Critical,
            "HIGH" => AlertSeverity::High,
            "MEDIUM" => AlertSeverity::Medium,
            "LOW" => AlertSeverity::Low,
            _ => AlertSeverity::Info,
        };
        Self {
            id,
            name,
            severity: sev,
            condition,
        }
    }
}

#[async_trait]
impl Rule for GenericRule {
    fn name(&self) -> &str {
        &self.name
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn log_types(&self) -> Vec<LogTag> {
        // Generic rules can apply to any log for now.
        // In a more advanced version, we could infer this from the condition.
        vec![LogTag::Auth, LogTag::Network, LogTag::Malware]
    }

    async fn evaluate(&self, log: &Log) -> Result<Option<Alert>> {
        if self.condition.evaluate(log) {
            Ok(Some(Alert {
                id: Uuid::new_v4(),
                rule_id: self.id.clone(),
                rule_name: self.name.clone(),
                severity: self.severity,
                description: format!("Rule triggered: {}", self.name),
                source_ip: log.source_ip.clone(),
                events: vec![log.clone()],
                first_seen: log.timestamp,
                last_seen: log.timestamp,
                status: crate::types::AlertStatus::New,
                events_count: 1,
            }))
        } else {
            Ok(None)
        }
    }
}
