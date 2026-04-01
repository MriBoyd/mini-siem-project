use async_trait::async_trait;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::Utc;

use crate::types::{Log, Alert, AlertSeverity, LogTag};
use crate::db::Cache;
use crate::detection::evaluator::RuleCondition;
use super::Rule;
use anyhow::Result;

#[derive(Debug, Serialize, Deserialize)]
pub struct CorrelationStage {
    pub name: String,
    pub condition: RuleCondition,
    pub min_count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CorrelationDefinition {
    pub window_seconds: u64,
    pub group_by: Vec<String>,
    pub stages: Vec<CorrelationStage>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CorrelationState {
    pub current_stage_idx: usize,
    pub events_in_stage: u32,
    pub start_time: i64,
    pub last_update: i64,
}

pub struct CorrelationRule {
    pub tenant_id: String,
    pub id: String,
    pub name: String,
    pub severity: AlertSeverity,
    pub definition: CorrelationDefinition,
    pub redis: Arc<dyn Cache>,
}

impl CorrelationRule {
    pub fn new(
        tenant_id: String,
        id: String,
        name: String,
        severity: String,
        definition: CorrelationDefinition,
        redis: Arc<dyn Cache>,
    ) -> Self {
        let sev = match severity.to_uppercase().as_str() {
            "CRITICAL" => AlertSeverity::Critical,
            "HIGH" => AlertSeverity::High,
            "MEDIUM" => AlertSeverity::Medium,
            "LOW" => AlertSeverity::Low,
            _ => AlertSeverity::Info,
        };
        Self {
            tenant_id,
            id,
            name,
            severity: sev,
            definition,
            redis,
        }
    }

    fn get_group_key(&self, log: &Log) -> String {
        // Build a composite key based on group_by fields
        let mut parts = Vec::new();
        for field in &self.definition.group_by {
             let val = match field.as_str() {
                "source_ip" => log.source_ip.clone(),
                "target_user" => log.target_user.clone().unwrap_or_default(),
                "event_type" => log.event_type.clone(),
                _ => "".to_string(), 
            };
            parts.push(val);
        }
        parts.join(":")
    }
}

#[async_trait]
impl Rule for CorrelationRule {
    fn name(&self) -> &str {
        &self.name
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    fn log_types(&self) -> Vec<LogTag> {
        // Correlation rules are broad
        vec![LogTag::Auth, LogTag::Network, LogTag::Malware] 
    }

    async fn evaluate(&self, log: &Log) -> Result<Option<Alert>> {
        let group_key = self.get_group_key(log);
        if group_key.is_empty() {
             return Ok(None);
        }
        
        let redis_key = format!("cep:{}:{}:{}", log.tenant_id, self.id, group_key);
        
        // 1. Fetch State
        let mut state = if let Some(state_json) = self.redis.get_string(&redis_key).await? {
            serde_json::from_str::<CorrelationState>(&state_json).unwrap_or_else(|_| CorrelationState {
                 current_stage_idx: 0,
                 events_in_stage: 0,
                 start_time: Utc::now().timestamp(),
                 last_update: Utc::now().timestamp(),
            })
        } else {
             // New state
             CorrelationState {
                 current_stage_idx: 0,
                 events_in_stage: 0,
                 start_time: Utc::now().timestamp(),
                 last_update: Utc::now().timestamp(),
             }
        };

        // 2. Check Window Expiry
        let now = Utc::now().timestamp();
        if now - state.start_time > self.definition.window_seconds as i64 {
            // Expired, reset
             state = CorrelationState {
                 current_stage_idx: 0,
                 events_in_stage: 0,
                 start_time: now,
                 last_update: now,
             };
        }

        // 3. Evaluate against Current Stage
        if let Some(stage) = self.definition.stages.get(state.current_stage_idx) {
            if stage.condition.evaluate(log) {
                state.events_in_stage += 1;
                state.last_update = now;
                
                // Check if stage complete
                if state.events_in_stage >= stage.min_count {
                    // Advance Stage
                    state.current_stage_idx += 1;
                    state.events_in_stage = 0;
                    
                    // Check if Rule Complete
                    if state.current_stage_idx >= self.definition.stages.len() {
                        // TRIGGER ALERT!
                        // Clear state
                        let _ = self.redis.set_string(&redis_key, "", Some(1)).await; // expire immediately

                         return Ok(Some(Alert {
                            id: Uuid::new_v4(),
                            tenant_id: log.tenant_id.clone(),
                            rule_id: self.id.clone(),
                            rule_name: self.name.clone(),
                            severity: self.severity,
                            description: format!("Correlation rule triggered: {}", self.name),
                            source_ip: log.source_ip.clone(), 
                            events: vec![log.clone()], // In ideal world, we'd fetch all previous events.
                            first_seen: log.timestamp,
                            last_seen: log.timestamp,
                            status: crate::types::AlertStatus::New,
                            events_count: 1,
                        }));
                    }
                }
                
                // Save State
                let json = serde_json::to_string(&state)?;
                self.redis.set_string(&redis_key, &json, Some(self.definition.window_seconds)).await?;
            }
        }

        Ok(None)
    }
}
