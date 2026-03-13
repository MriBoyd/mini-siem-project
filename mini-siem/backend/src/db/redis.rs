use redis::{aio::ConnectionManager, AsyncCommands, Client};
use tracing::info;
use anyhow::Result;

pub struct RedisCache {
    conn: ConnectionManager,
}

#[allow(dead_code)]
impl RedisCache {
    pub async fn new(redis_url: &str) -> Result<Self> {
        info!("🗄️  Connecting to Redis...");
        
        let client = Client::open(redis_url)?;
        let conn = ConnectionManager::new(client).await?;
        
        info!("✅ Connected to Redis");
        
        Ok(Self { conn })
    }
    
    // Atomic counter increment with expiry
    pub async fn increment_counter(&mut self, key: &str, expiry_seconds: u64) -> Result<u32> {
        let count: u32 = self.conn.incr(key, 1).await?;
        
        // Set expiry on first increment
        if count == 1 {
            let _: () = self.conn.expire(key, expiry_seconds as i64).await?;
        }
        
        Ok(count)
    }
    
    // Get counter value
    pub async fn get_counter(&mut self, key: &str) -> Result<Option<u32>> {
        let count: Option<u32> = self.conn.get(key).await?;
        Ok(count)
    }
    
    // Store alert suppression state
    pub async fn set_suppression(&mut self, rule_id: &str, ip: &str, ttl_seconds: u64) -> Result<()> {
        let key = format!("suppress:{}:{}", rule_id, ip);
        let _: () = self.conn.set_ex(key, "1", ttl_seconds).await?;
        Ok(())
    }
    
    // Check if suppressed
    pub async fn is_suppressed(&mut self, rule_id: &str, ip: &str) -> Result<bool> {
        let key = format!("suppress:{}:{}", rule_id, ip);
        let exists: bool = self.conn.exists(key).await?;
        Ok(exists)
    }
    
    // Store IP reputation (from threat intel)
    pub async fn set_ip_reputation(&mut self, ip: &str, score: u8, ttl_seconds: u64) -> Result<()> {
        let key = format!("reputation:{}", ip);
        let _: () = self.conn.set_ex(key, score, ttl_seconds).await?;
        Ok(())
    }
    
    // Get IP reputation
    pub async fn get_ip_reputation(&mut self, ip: &str) -> Result<Option<u8>> {
        let key = format!("reputation:{}", ip);
        let score: Option<u8> = self.conn.get(key).await?;
        Ok(score)
    }
}