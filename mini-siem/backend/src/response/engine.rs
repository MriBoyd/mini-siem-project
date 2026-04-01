use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error};
use crate::types::{Alert, AlertSeverity};
use super::actions::ResponseAction;

pub struct ResponseEngine {
    // Map: (Tenant ID, Rule ID) -> List of Actions
    rule_policies: Arc<RwLock<HashMap<(String, String), Vec<Arc<dyn ResponseAction>>>>>,
    // Map: (Tenant ID, Severity) -> List of Actions, where "*" is the global fallback.
    severity_policies: Arc<RwLock<HashMap<(String, AlertSeverity), Vec<Arc<dyn ResponseAction>>>>>,
}

impl ResponseEngine {
    pub fn new() -> Self {
        Self {
            rule_policies: Arc::new(RwLock::new(HashMap::new())),
            severity_policies: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_rule_policy(&self, tenant_id: &str, rule_id: &str, action: Arc<dyn ResponseAction>) {
        let mut policies = self.rule_policies.write().await;
        policies.entry((tenant_id.to_string(), rule_id.to_string()))
            .or_insert_with(Vec::new)
            .push(action);
    }

    pub async fn add_severity_policy(&self, tenant_id: Option<&str>, severity: AlertSeverity, action: Arc<dyn ResponseAction>) {
        let mut policies = self.severity_policies.write().await;
        policies.entry((tenant_id.unwrap_or("*").to_string(), severity))
            .or_insert_with(Vec::new)
            .push(action);
    }

    pub async fn add_global_severity_policy(&self, severity: AlertSeverity, action: Arc<dyn ResponseAction>) {
        self.add_severity_policy(None, severity, action).await;
    }

    pub async fn handle_alert(&self, alert: &Alert) {
        let mut actions_to_run: Vec<Arc<dyn ResponseAction>> = Vec::new();

        // 1. Check specific rule policies
        {
            let rule_policies = self.rule_policies.read().await;
            if let Some(actions) = rule_policies.get(&(alert.tenant_id.clone(), alert.rule_id.clone())) {
                for action in actions {
                    actions_to_run.push(Arc::clone(action));
                }
            } else if let Some(actions) = rule_policies.get(&("*".to_string(), alert.rule_id.clone())) {
                for action in actions {
                    actions_to_run.push(Arc::clone(action));
                }
            }
        }

        // 2. Check severity policies
        {
            let severity_policies = self.severity_policies.read().await;
            if let Some(actions) = severity_policies.get(&(alert.tenant_id.clone(), alert.severity)) {
                for action in actions {
                    actions_to_run.push(Arc::clone(action));
                }
            }
            if let Some(actions) = severity_policies.get(&("*".to_string(), alert.severity)) {
                for action in actions {
                    actions_to_run.push(Arc::clone(action));
                }
            }
        }

        if actions_to_run.is_empty() {
            return;
        }

        info!("⚡ Spawning response task with {} actions for alert {}", actions_to_run.len(), alert.id);

        let alert_clone = alert.clone();
        tokio::spawn(async move {
            for action in actions_to_run {
                let action_name = action.name().to_string();
                info!("▶️ Starting Action '{}' for alert {}", action_name, alert_clone.id);
                match action.execute(&alert_clone).await {
                    Ok(_) => info!("✅ Action '{}' completed for alert {}", action_name, alert_clone.id),
                    Err(e) => error!("❌ Action '{}' failed for alert {}: {}", action_name, alert_clone.id, e),
                }
            }
        });
    }
}
