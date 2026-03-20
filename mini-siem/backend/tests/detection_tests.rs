use std::sync::Arc;
use tokio::sync::Mutex;
use async_trait::async_trait;
use mini_siem::types::Log;
use mini_siem::db::Cache;
use mini_siem::detection::rules::brute_force::BruteForceRule;
use mini_siem::detection::rules::Rule;
use anyhow::Result;

struct MockCache {
    counter: Mutex<u32>,
}

#[async_trait]
impl Cache for MockCache {
    async fn increment_counter(&self, _key: &str, _expiry_seconds: u64) -> Result<u32> {
        let mut count = self.counter.lock().await;
        *count += 1;
        Ok(*count)
    }
    
    async fn get_counter(&self, _key: &str) -> Result<Option<u32>> { Ok(None) }
    async fn set_suppression(&self, _rule_id: &str, _ip: &str, _ttl_seconds: u64) -> Result<()> { Ok(()) }
    async fn is_suppressed(&self, _rule_id: &str, _ip: &str) -> Result<bool> { Ok(false) }
    async fn set_ip_reputation(&self, _ip: &str, _score: u8, _ttl_seconds: u64) -> Result<()> { Ok(()) }
    async fn get_ip_reputation(&self, _ip: &str) -> Result<Option<u8>> { Ok(None) }
    async fn allow_sliding_window(&self, _key: &str, _window_ms: u64, _limit: u32) -> Result<bool> { Ok(true) }
    async fn store_refresh_token(&self, _user_id: &str, _token: &str, _ttl_seconds: u64) -> Result<()> { Ok(()) }
    async fn get_user_id_by_refresh_token(&self, _token: &str) -> Result<Option<String>> { Ok(None) }
    async fn revoke_refresh_token(&self, _token: &str) -> Result<()> { Ok(()) }
    async fn revoke_all_user_tokens(&self, _user_id: &str) -> Result<()> { Ok(()) }
}

#[tokio::test]
async fn test_brute_force_rule_trigger() {
    let mock_cache = Arc::new(MockCache { counter: Mutex::new(0) });
    let rule = BruteForceRule::new(
        "rule_1".to_string(),
        "Brute Force Test".to_string(),
        3, // threshold
        60, // window
        mock_cache.clone(),
    );

    let log = Log::new(
        "login_failed".to_string(),
        "1.2.3.4".to_string(),
        "Failed password".to_string(),
    );

    // Attempt 1
    let res = rule.evaluate(&log).await.unwrap();
    assert!(res.is_none());

    // Attempt 2
    let res = rule.evaluate(&log).await.unwrap();
    assert!(res.is_none());

    // Attempt 3 - Trigger!
    let res = rule.evaluate(&log).await.unwrap();
    assert!(res.is_some());
    let alert = res.unwrap();
    assert_eq!(alert.rule_id, "rule_1");
    assert_eq!(alert.source_ip, "1.2.3.4");
}
