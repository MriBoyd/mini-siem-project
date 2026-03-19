use redis::{aio::ConnectionManager, AsyncCommands, Client};
use tracing::info;
use anyhow::Result;

#[derive(Clone)]
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
    pub async fn increment_counter(&self, key: &str, expiry_seconds: u64) -> Result<u32> {
        let mut conn = self.conn.clone();
        let count: u32 = conn.incr(key, 1).await?;
        
        // Set expiry on first increment
        if count == 1 {
            let _: () = conn.expire(key, expiry_seconds as i64).await?;
        }
        
        Ok(count)
    }
    
    // Get counter value
    pub async fn get_counter(&self, key: &str) -> Result<Option<u32>> {
        let mut conn = self.conn.clone();
        let count: Option<u32> = conn.get(key).await?;
        Ok(count)
    }
    
    // Store alert suppression state
    pub async fn set_suppression(&self, rule_id: &str, ip: &str, ttl_seconds: u64) -> Result<()> {
        let mut conn = self.conn.clone();
        let key = format!("suppress:{}:{}", rule_id, ip);
        let _: () = conn.set_ex(key, "1", ttl_seconds).await?;
        Ok(())
    }
    
    // Check if suppressed
    pub async fn is_suppressed(&self, rule_id: &str, ip: &str) -> Result<bool> {
        let mut conn = self.conn.clone();
        let key = format!("suppress:{}:{}", rule_id, ip);
        let exists: bool = conn.exists(key).await?;
        Ok(exists)
    }
    
    // Store IP reputation (from threat intel)
    pub async fn set_ip_reputation(&self, ip: &str, score: u8, ttl_seconds: u64) -> Result<()> {
        let mut conn = self.conn.clone();
        let key = format!("reputation:{}", ip);
        let _: () = conn.set_ex(key, score, ttl_seconds).await?;
        Ok(())
    }
    
    // Get IP reputation
    pub async fn get_ip_reputation(&self, ip: &str) -> Result<Option<u8>> {
        let mut conn = self.conn.clone();
        let key = format!("reputation:{}", ip);
        let score: Option<u8> = conn.get(key).await?;
        Ok(score)
    }

    // Sliding-window rate limiter using sorted set of timestamps (milliseconds)
    // Returns true if allowed, false if rate limit exceeded.
    pub async fn allow_sliding_window(&self, key: &str, window_ms: u64, limit: u32) -> Result<bool> {
        let mut conn = self.conn.clone();
        // Lua script to remove old entries, count, add current timestamp if under limit, and set TTL
        let script = r#"
        local key = KEYS[1]
        local now = tonumber(ARGV[1])
        local window = tonumber(ARGV[2])
        local limit = tonumber(ARGV[3])
        local min = now - window
        redis.call('ZREMRANGEBYSCORE', key, 0, min)
        local current = redis.call('ZCARD', key)
        if tonumber(current) < limit then
            redis.call('ZADD', key, now, tostring(now))
            redis.call('PEXPIRE', key, window)
            return 1
        end
        return 0
        "#;

        // get current time in milliseconds
        use chrono::Utc;
        let now = Utc::now().timestamp_millis();

        // execute script
        let res: i32 = redis::Script::new(script)
            .key(key)
            .arg(now)
            .arg(window_ms)
            .arg(limit)
            .invoke_async(&mut conn)
            .await?;

        Ok(res == 1)
    }

    // Refresh token management
    pub async fn store_refresh_token(&self, user_id: &str, token: &str, ttl_seconds: u64) -> Result<()> {
        let mut conn = self.conn.clone();
        // Key: refresh_token:{token}, Value: {user_id}
        // Also keep a way to revoke all tokens for a user: user_tokens:{user_id} -> set of tokens
        let token_key = format!("refresh_token:{}", token);
        let user_tokens_key = format!("user_tokens:{}", user_id);
        
        let _: () = conn.set_ex(&token_key, user_id, ttl_seconds).await?;
        let _: () = conn.sadd(&user_tokens_key, token).await?;
        let _: () = conn.expire(&user_tokens_key, ttl_seconds as i64).await?;
        
        Ok(())
    }

    pub async fn get_user_id_by_refresh_token(&self, token: &str) -> Result<Option<String>> {
        let mut conn = self.conn.clone();
        let token_key = format!("refresh_token:{}", token);
        let user_id: Option<String> = conn.get(token_key).await?;
        Ok(user_id)
    }

    pub async fn revoke_refresh_token(&self, token: &str) -> Result<()> {
        let mut conn = self.conn.clone();
        if let Some(user_id) = self.get_user_id_by_refresh_token(token).await? {
            let token_key = format!("refresh_token:{}", token);
            let user_tokens_key = format!("user_tokens:{}", user_id);
            let _: () = conn.del(token_key).await?;
            let _: () = conn.srem(user_tokens_key, token).await?;
        }
        Ok(())
    }

    pub async fn revoke_all_user_tokens(&self, user_id: &str) -> Result<()> {
        let mut conn = self.conn.clone();
        let user_tokens_key = format!("user_tokens:{}", user_id);
        let tokens: Vec<String> = conn.smembers(&user_tokens_key).await?;
        
        for token in tokens {
            let token_key = format!("refresh_token:{}", token);
            let _: () = conn.del(token_key).await?;
        }
        let _: () = conn.del(user_tokens_key).await?;
        
        Ok(())
    }
}
