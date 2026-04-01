use async_trait::async_trait;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{Log, Alert, AlertSeverity, LogTag};
use crate::db::Cache;
use crate::detection::evaluator::RuleCondition;
use super::Rule;
use anyhow::Result;

fn default_version() -> u64 {
    1
}

fn default_max_active_groups() -> usize {
    4096
}

fn default_watermark_lateness_seconds() -> i64 {
    30
}

fn default_state_ttl_seconds() -> u64 {
    900
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationEvictionPolicy {
    OldestFirst,
    DropNewest,
}

impl Default for CorrelationEvictionPolicy {
    fn default() -> Self {
        Self::OldestFirst
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CorrelationStage {
    pub name: String,
    pub condition: RuleCondition,
    pub min_count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CorrelationDefinition {
    pub window_seconds: u64,
    #[serde(default = "default_version")]
    pub version: u64,
    #[serde(default = "default_max_active_groups")]
    pub max_active_groups: usize,
    #[serde(default = "default_watermark_lateness_seconds")]
    pub watermark_lateness_seconds: i64,
    #[serde(default = "default_state_ttl_seconds")]
    pub state_ttl_seconds: u64,
    #[serde(default)]
    pub eviction_policy: CorrelationEvictionPolicy,
    pub group_by: Vec<String>,
    pub stages: Vec<CorrelationStage>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CorrelationState {
    pub group_key: String,
    pub current_stage_idx: usize,
    pub events_in_stage: u32,
    pub window_start_event_ts: i64,
    pub max_event_ts: i64,
    pub last_event_ts: i64,
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

    fn namespace(&self) -> String {
        format!("cep:{}:{}:v{}", self.tenant_id, self.id, self.definition.version)
    }

    fn state_key(&self, group_key: &str) -> String {
        let mut hasher = DefaultHasher::new();
        group_key.hash(&mut hasher);
        let fingerprint = hasher.finish();
        format!("{}:state:{:016x}", self.namespace(), fingerprint)
    }

    fn active_index_key(&self) -> String {
        format!("{}:active", self.namespace())
    }

    fn state_ttl_seconds(&self) -> u64 {
        let base = self.definition.window_seconds
            .saturating_add(self.definition.watermark_lateness_seconds.max(0) as u64)
            .saturating_add(60);
        self.definition.state_ttl_seconds.max(base)
    }

    fn is_stale_by_watermark(&self, state: &CorrelationState, event_ts: i64) -> bool {
        let watermark = state.max_event_ts.saturating_sub(self.definition.watermark_lateness_seconds.max(0));
        event_ts < watermark
    }

    fn reset_state(&self, group_key: String, event_ts: i64) -> CorrelationState {
        CorrelationState {
            group_key,
            current_stage_idx: 0,
            events_in_stage: 0,
            window_start_event_ts: event_ts,
            max_event_ts: event_ts,
            last_event_ts: event_ts,
        }
    }

    async fn load_state(&self, state_key: &str, group_key: &str, event_ts: i64) -> Result<CorrelationState> {
        if let Some(state_json) = self.redis.get_string(state_key).await? {
            match serde_json::from_str::<CorrelationState>(&state_json) {
                Ok(state) if state.group_key == group_key => Ok(state),
                Ok(_) => Ok(self.reset_state(group_key.to_string(), event_ts)),
                Err(_) => Ok(self.reset_state(group_key.to_string(), event_ts)),
            }
        } else {
            Ok(self.reset_state(group_key.to_string(), event_ts))
        }
    }

    async fn evict_if_needed(&self, state_key: &str) -> Result<bool> {
        let index_key = self.active_index_key();
        if self.redis.zcard(&index_key).await? < self.definition.max_active_groups as u64 {
            return Ok(true);
        }

        match self.definition.eviction_policy {
            CorrelationEvictionPolicy::OldestFirst => {
                if let Some(oldest_key) = self.redis.zpopmin(&index_key).await? {
                    let _ = self.redis.delete_key(&oldest_key).await;
                    Ok(true)
                } else {
                    // If the index was empty but zcard claimed otherwise, proceed cautiously.
                    Ok(true)
                }
            }
            CorrelationEvictionPolicy::DropNewest => {
                tracing::warn!("Correlation state cap reached for {}; dropping newest group state", self.namespace());
                let _ = self.redis.zrem(&index_key, state_key).await;
                Ok(false)
            }
        }
    }

    async fn persist_state(&self, state_key: &str, state: &CorrelationState) -> Result<()> {
        let json = serde_json::to_string(state)?;
        let ttl = self.state_ttl_seconds();
        self.redis.set_string(state_key, &json, Some(ttl)).await?;

        let index_key = self.active_index_key();
        self.redis.zadd(&index_key, state_key, state.last_event_ts).await?;
        self.redis.expire_key(&index_key, ttl).await?;
        Ok(())
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

        let event_ts = log.timestamp.timestamp();
        let state_key = self.state_key(&group_key);
        let mut state = self.load_state(&state_key, &group_key, event_ts).await?;

        // Watermark-based event-time gating: if this event is older than the
        // allowed lateness behind the newest event seen for the group, ignore it.
        if self.is_stale_by_watermark(&state, event_ts) {
            tracing::debug!(
                tenant_id = %log.tenant_id,
                rule_id = %self.id,
                group_key = %group_key,
                event_ts = event_ts,
                max_event_ts = state.max_event_ts,
                "Dropping late correlation event behind watermark"
            );
            return Ok(None);
        }

        if event_ts > state.max_event_ts {
            state.max_event_ts = event_ts;
        }
        state.last_event_ts = event_ts;

        // Reset the window when the watermark has moved past the configured
        // event-time window.
        let watermark = state.max_event_ts.saturating_sub(self.definition.watermark_lateness_seconds.max(0));
        if watermark - state.window_start_event_ts > self.definition.window_seconds as i64 {
            state = self.reset_state(group_key.clone(), event_ts);
        }

        // Enforce bounded cardinality before persisting a brand-new group.
        let is_new_group = state.current_stage_idx == 0 && state.events_in_stage == 0 && state.window_start_event_ts == event_ts && state.max_event_ts == event_ts;
        if is_new_group {
            let allowed = self.evict_if_needed(&state_key).await?;
            if !allowed {
                return Ok(None);
            }
        }

        // Evaluate against current stage.
        if let Some(stage) = self.definition.stages.get(state.current_stage_idx) {
            if stage.condition.evaluate(log) {
                state.events_in_stage += 1;
                state.last_event_ts = event_ts;
                
                // Check if stage complete
                if state.events_in_stage >= stage.min_count {
                    // Advance Stage
                    state.current_stage_idx += 1;
                    state.events_in_stage = 0;
                    
                    // Check if Rule Complete
                    if state.current_stage_idx >= self.definition.stages.len() {
                        // TRIGGER ALERT!
                        // Clear state
                        let _ = self.redis.delete_key(&state_key).await;
                        let _ = self.redis.zrem(&self.active_index_key(), &state_key).await;

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
            }
        }

        // Save state and refresh the bounded index.
        self.persist_state(&state_key, &state).await?;

        Ok(None)
    }
}
