use redis::{aio::ConnectionManager, AsyncCommands, Client};
use tracing::info;
use anyhow::Result;
use async_trait::async_trait;
use super::cache::Cache;
use dashmap::DashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct RedisCache {
    conn: ConnectionManager,
    // Lightweight in-memory L1 cache for hot-path counters
    l1: Arc<DashMap<String, u64>>,
}

#[async_trait]
impl Cache for RedisCache {
    // Atomic counter increment with expiry
    async fn increment_counter(&self, key: &str, expiry_seconds: u64) -> Result<u32> {
        let mut conn = self.conn.clone();
        let count: u32 = conn.incr(key, 1).await?;

        // Set expiry on first increment
        if count == 1 {
            let _: () = conn.expire(key, expiry_seconds as i64).await?;
        }

        // Update L1 cache
        self.l1.insert(key.to_string(), count as u64);

        Ok(count)
    }
    
    // Get counter value
    async fn get_counter(&self, key: &str) -> Result<Option<u32>> {
        // Check L1 cache first
        if let Some(v) = self.l1.get(key) {
            return Ok(Some(*v.value() as u32));
        }

        let mut conn = self.conn.clone();
        let count: Option<u32> = conn.get(key).await?;
        if let Some(c) = count {
            self.l1.insert(key.to_string(), c as u64);
        }
        Ok(count)
    }

    async fn set_counter(&self, key: &str, value: u64, expiry_seconds: Option<u64>) -> Result<()> {
        let mut conn = self.conn.clone();
        let _: () = conn.set(key, value).await?;
        if let Some(exp) = expiry_seconds {
            let _: () = conn.expire(key, exp as i64).await?;
        }
        Ok(())
    }

    async fn decrement_counter(&self, key: &str) -> Result<u32> {
        let mut conn = self.conn.clone();
        // DECR returns value which may be negative; clamp at 0
        let val: i64 = conn.decr(key, 1).await?;
        let v = if val < 0 { 0 } else { val as u32 };
        // Update L1 cache
        self.l1.insert(key.to_string(), v as u64);
        Ok(v)
    }
    
    // Store alert suppression state
    async fn set_suppression(&self, rule_id: &str, ip: &str, ttl_seconds: u64) -> Result<()> {
        let mut conn = self.conn.clone();
        let key = format!("suppress:{}:{}", rule_id, ip);
        let _: () = conn.set_ex(key, "1", ttl_seconds).await?;
        Ok(())
    }
    
    // Check if suppressed
    async fn is_suppressed(&self, rule_id: &str, ip: &str) -> Result<bool> {
        let mut conn = self.conn.clone();
        let key = format!("suppress:{}:{}", rule_id, ip);
        let exists: bool = conn.exists(key).await?;
        Ok(exists)
    }
    
    // Store IP reputation (from threat intel)
    async fn set_ip_reputation(&self, ip: &str, score: u8, ttl_seconds: u64) -> Result<()> {
        let mut conn = self.conn.clone();
        let key = format!("reputation:{}", ip);
        let _: () = conn.set_ex(key, score, ttl_seconds).await?;
        Ok(())
    }
    
    // Get IP reputation
    async fn get_ip_reputation(&self, ip: &str) -> Result<Option<u8>> {
        let mut conn = self.conn.clone();
        let key = format!("reputation:{}", ip);
        let score: Option<u8> = conn.get(key).await?;
        Ok(score)
    }

    // Sliding-window rate limiter using sorted set of timestamps (milliseconds)
    // Returns true if allowed, false if rate limit exceeded.
    async fn allow_sliding_window(&self, key: &str, window_ms: u64, limit: u32) -> Result<bool> {
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
    async fn store_refresh_token(&self, user_id: &str, token: &str, ttl_seconds: u64) -> Result<()> {
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

    async fn get_user_id_by_refresh_token(&self, token: &str) -> Result<Option<String>> {
        let mut conn = self.conn.clone();
        let token_key = format!("refresh_token:{}", token);
        let user_id: Option<String> = conn.get(token_key).await?;
        Ok(user_id)
    }

    async fn revoke_refresh_token(&self, token: &str) -> Result<()> {
        let mut conn = self.conn.clone();
        if let Some(user_id) = self.get_user_id_by_refresh_token(token).await? {
            let token_key = format!("refresh_token:{}", token);
            let user_tokens_key = format!("user_tokens:{}", user_id);
            let _: () = conn.del(token_key).await?;
            let _: () = conn.srem(user_tokens_key, token).await?;
        }
        Ok(())
    }

    async fn revoke_all_user_tokens(&self, user_id: &str) -> Result<()> {
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

impl RedisCache {
    pub async fn new(redis_url: &str) -> Result<Self> {
        info!("🗄️  Connecting to Redis...");
        
        let client = Client::open(redis_url)?;
        let conn = ConnectionManager::new(client).await?;
        
        info!("✅ Connected to Redis");
        Ok(Self { conn, l1: Arc::new(DashMap::new()) })
    }

    // Atomic increment for alert-related counters using Lua script to minimize roundtrips.
    // Increments `siem:stats:total_alerts` and `siem:stats:active_alerts` always, and
    // `siem:stats:critical_alerts` when `is_critical` is true. Returns tuple (ta, aa, ca).
    pub async fn inc_alert_counters(&self, is_critical: bool, expiry_seconds: u64) -> Result<(u32,u32,u32)> {
        let mut conn = self.conn.clone();

        let script = r#"
        local ta_key = KEYS[1]
        local aa_key = KEYS[2]
        local ca_key = KEYS[3]
        local is_crit = tonumber(ARGV[1])
        local exp = tonumber(ARGV[2])

        local ta = redis.call('INCR', ta_key)
        redis.call('EXPIRE', ta_key, exp)
        local aa = redis.call('INCR', aa_key)
        redis.call('EXPIRE', aa_key, exp)
        local ca = 0
        if is_crit == 1 then
            ca = redis.call('INCR', ca_key)
            redis.call('EXPIRE', ca_key, exp)
        else
            ca = redis.call('GET', ca_key) or 0
        end
        return {ta, aa, ca}
        "#;

        let keys = vec!["siem:stats:total_alerts", "siem:stats:active_alerts", "siem:stats:critical_alerts"];

        // Invoke script with numeric args to avoid temporary &str lifetimes
        let res: Vec<i64> = redis::Script::new(script)
            .key(keys[0])
            .key(keys[1])
            .key(keys[2])
            .arg(if is_critical { 1 } else { 0 })
            .arg(expiry_seconds)
            .invoke_async(&mut conn)
            .await?;

        // Ensure we have three values
        let ta = *res.get(0).unwrap_or(&0);
        let aa = *res.get(1).unwrap_or(&0);
        let ca = *res.get(2).unwrap_or(&0);

        // Update L1 cache
        self.l1.insert(keys[0].to_string(), ta as u64);
        self.l1.insert(keys[1].to_string(), aa as u64);
        self.l1.insert(keys[2].to_string(), ca as u64);

        Ok((ta as u32, aa as u32, ca as u32))
    }
}
