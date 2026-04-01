use async_trait::async_trait;
use anyhow::Result;

#[async_trait]
pub trait Cache: Send + Sync {
    async fn increment_counter(&self, key: &str, expiry_seconds: u64) -> Result<u32>;
    async fn get_counter(&self, key: &str) -> Result<Option<u32>>;
    async fn decrement_counter(&self, key: &str) -> Result<u32>;
    async fn set_counter(&self, key: &str, value: u64, expiry_seconds: Option<u64>) -> Result<()>;
    
    async fn set_suppression(&self, rule_id: &str, ip: &str, ttl_seconds: u64) -> Result<()>;
    async fn is_suppressed(&self, rule_id: &str, ip: &str) -> Result<bool>;
    
    async fn set_ip_reputation(&self, ip: &str, score: u8, ttl_seconds: u64) -> Result<()>;
    async fn get_ip_reputation(&self, ip: &str) -> Result<Option<u8>>;
    
    async fn allow_sliding_window(&self, key: &str, window_ms: u64, limit: u32) -> Result<bool>;
    
    async fn store_refresh_token(&self, user_id: &str, tenant_id: &str, token: &str, ttl_seconds: u64) -> Result<()>;
    async fn get_user_id_by_refresh_token(&self, token: &str) -> Result<Option<String>>;
    async fn revoke_refresh_token(&self, token: &str) -> Result<()>;
    async fn revoke_all_user_tokens(&self, user_id: &str) -> Result<()>;
    async fn delete_key(&self, key: &str) -> Result<()>;

    async fn set_string(&self, key: &str, value: &str, expiry_seconds: Option<u64>) -> Result<()>;
    async fn get_string(&self, key: &str) -> Result<Option<String>>;
}
