use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use async_trait::async_trait;
use mini_siem::db::Cache;
use mini_siem::types::Log;
use mini_siem::detection::evaluator::RuleCondition;
use mini_siem::detection::rules::correlation::{CorrelationRule, CorrelationDefinition, CorrelationStage};
use mini_siem::detection::rules::Rule;
use serde_json::json;
use anyhow::Result;

struct StatefulMockCache {
    store: Mutex<HashMap<String, String>>,
}

impl StatefulMockCache {
    fn new() -> Self {
        Self { store: Mutex::new(HashMap::new()) }
    }
}

#[async_trait]
impl Cache for StatefulMockCache {
    async fn increment_counter(&self, _key: &str, _expiry: u64) -> Result<u32> { Ok(1) }
    async fn get_counter(&self, _key: &str) -> Result<Option<u32>> { Ok(None) }
    async fn decrement_counter(&self, _key: &str) -> Result<u32> { Ok(0) }
    async fn set_counter(&self, _key: &str, _val: u64, _exp: Option<u64>) -> Result<()> { Ok(()) }
    async fn set_suppression(&self, _rid: &str, _ip: &str, _ttl: u64) -> Result<()> { Ok(()) }
    async fn is_suppressed(&self, _rid: &str, _ip: &str) -> Result<bool> { Ok(false) }
    async fn set_ip_reputation(&self, _ip: &str, _score: u8, _ttl: u64) -> Result<()> { Ok(()) }
    async fn get_ip_reputation(&self, _ip: &str) -> Result<Option<u8>> { Ok(None) }
    async fn allow_sliding_window(&self, _key: &str, _win: u64, _limit: u32) -> Result<bool> { Ok(true) }
    async fn store_refresh_token(&self, _uid: &str, _tok: &str, _ttl: u64) -> Result<()> { Ok(()) }
    async fn get_user_id_by_refresh_token(&self, _tok: &str) -> Result<Option<String>> { Ok(None) }
    async fn revoke_refresh_token(&self, _tok: &str) -> Result<()> { Ok(()) }
    async fn revoke_all_user_tokens(&self, _uid: &str) -> Result<()> { Ok(()) }
    
    async fn set_string(&self, key: &str, value: &str, _expiry: Option<u64>) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        store.insert(key.to_string(), value.to_string());
        Ok(())
    }
    
    async fn get_string(&self, key: &str) -> Result<Option<String>> {
        let store = self.store.lock().unwrap();
        Ok(store.get(key).cloned())
    }
}

#[tokio::test]
async fn test_correlation_sequence() {
    let cache = Arc::new(StatefulMockCache::new());
    
    // Rule: 2 Failed Logins then 1 VPN Login within 10 seconds.
    let def = CorrelationDefinition {
        window_seconds: 10,
        group_by: vec!["source_ip".to_string()],
        stages: vec![
            CorrelationStage {
                name: "failed_login".to_string(),
                condition: RuleCondition::Field {
                    field: "event_type".to_string(),
                    op: "==".to_string(),
                    value: json!("login_failed"),
                },
                min_count: 2,
            },
            CorrelationStage {
                name: "vpn_login".to_string(),
                condition: RuleCondition::Field {
                    field: "service".to_string(),
                    op: "==".to_string(),
                    value: json!("vpn"),
                },
                min_count: 1,
            }
        ]
    };

    let rule = CorrelationRule::new(
        "corr_1".to_string(),
        "Brute Force then VPN".to_string(),
        "High".to_string(),
        def,
        cache.clone(),
    );

    let log_fail = Log::new("login_failed".to_string(), "10.0.0.1".to_string(), "".to_string());
    let mut log_vpn = Log::new("login_success".to_string(), "10.0.0.1".to_string(), "".to_string());
    log_vpn.service = Some("vpn".to_string());

    // Step 1: Failed Login (1/2)
    let res = rule.evaluate(&log_fail).await.unwrap();
    assert!(res.is_none());

    // Step 2: Failed Login (2/2) -> Stage Complete, moves to next stage
    let res = rule.evaluate(&log_fail).await.unwrap();
    assert!(res.is_none());
    
    // Check internal state via cache? 
    // Key: cep:corr_1:10.0.0.1
    let state_str = cache.get_string("cep:corr_1:10.0.0.1").await.unwrap().unwrap();
    assert!(state_str.contains("\"current_stage_idx\":1")); // Should be at stage 1 (0-indexed)

    // Step 3: VPN Login (1/1) -> Rule Complete -> Alert
    let res = rule.evaluate(&log_vpn).await.unwrap();
    assert!(res.is_some());
    let alert = res.unwrap();
    assert_eq!(alert.rule_name, "Brute Force then VPN");
}

#[tokio::test]
async fn test_correlation_grouping() {
    let cache = Arc::new(StatefulMockCache::new());
    // Simple 2-event sequence
    let def = CorrelationDefinition {
        window_seconds: 10,
        group_by: vec!["source_ip".to_string()],
        stages: vec![
            CorrelationStage {
                name: "any".to_string(),
                condition: RuleCondition::Field { field: "event_type".to_string(), op: "==".to_string(), value: json!("test") },
                min_count: 2,
            }
        ]
    };
    let rule = CorrelationRule::new("corr_2".to_string(), "Test".to_string(), "Low".to_string(), def, cache);

    let log1 = Log::new("test".to_string(), "IP_A".to_string(), "".to_string());
    let log2 = Log::new("test".to_string(), "IP_B".to_string(), "".to_string());

    // IP_A: 1/2
    assert!(rule.evaluate(&log1).await.unwrap().is_none());
    // IP_B: 1/2
    assert!(rule.evaluate(&log2).await.unwrap().is_none());
    
    // IP_A: 2/2 -> Trigger
    assert!(rule.evaluate(&log1).await.unwrap().is_some());
    
    // IP_B: Still 1/2 (implied, no trigger)
    assert!(rule.evaluate(&log2).await.unwrap().is_some()); // Now 2/2 -> Trigger
}
