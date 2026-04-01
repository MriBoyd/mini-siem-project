use redis::{aio::ConnectionManager, AsyncCommands, Client};
use tracing::info;
use anyhow::Result;
use async_trait::async_trait;
use super::cache::Cache;
use dashmap::DashMap;
use std::sync::Arc;
use chrono::Utc;
use tokio::time::{sleep, Duration};
use tokio::sync::Mutex as AsyncMutex;
use crate::auth::hash_refresh_token;

#[derive(Clone)]
pub struct RedisCache {
    conn: ConnectionManager,
    // Lightweight in-memory L1 cache for hot-path counters
    // value, last_updated_unix_sec, access hits
    l1: Arc<DashMap<String, L1Entry>>,
    // Per-key async locks to prevent stampedes during refreshes
    refresh_locks: Arc<DashMap<String, Arc<AsyncMutex<()>>>>,
}

#[derive(Clone, Debug)]
pub struct L1Entry {
    pub value: u64,
    pub ts: i64,
    pub hits: u64,
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

        // Update L1 cache with timestamp
        let now = Utc::now().timestamp();
        self.l1.insert(key.to_string(), L1Entry { value: count as u64, ts: now, hits: 1 });

        Ok(count)
    }
    
    // Get counter value
    async fn get_counter(&self, key: &str) -> Result<Option<u32>> {
        // Check L1 cache first
        if let Some(v) = self.l1.get(key) {
            // increment hit counter (best-effort)
            let hits = v.value().hits.saturating_add(1);
            let val = v.value().value;
            let ts = v.value().ts;
            drop(v);
            self.l1.insert(key.to_string(), L1Entry { value: val, ts, hits });

            // If entry is stale, trigger background refresh (stale-while-revalidate)
            let now = Utc::now().timestamp();
            // refresh_if_older will be configured in maintenance; default to 30s here
            let refresh_if_older = 30;
            if now - ts > refresh_if_older {
                let cache = self.clone();
                let key_s = key.to_string();
                tokio::spawn(async move {
                    let _ = cache.refresh_key(&key_s).await;
                });
            }

            return Ok(Some(val as u32));
        }

        let mut conn = self.conn.clone();
        let count: Option<u32> = conn.get(key).await?;
        if let Some(c) = count {
            let now = Utc::now().timestamp();
            self.l1.insert(key.to_string(), L1Entry { value: c as u64, ts: now, hits: 1 });
        }
        Ok(count)
    }

    async fn set_counter(&self, key: &str, value: u64, expiry_seconds: Option<u64>) -> Result<()> {
        let mut conn = self.conn.clone();
        let _: () = conn.set(key, value).await?;
        if let Some(exp) = expiry_seconds {
            let _: () = conn.expire(key, exp as i64).await?;
        }
        // Update L1 cache so reads are consistent
        let now = Utc::now().timestamp();
        self.l1.insert(key.to_string(), L1Entry { value, ts: now, hits: 1 });
        Ok(())
    }

    async fn decrement_counter(&self, key: &str) -> Result<u32> {
        let mut conn = self.conn.clone();
        // DECR returns value which may be negative; clamp at 0
        let val: i64 = conn.decr(key, 1).await?;
        let v = if val < 0 { 0 } else { val as u32 };
        // Update L1 cache
        let now = Utc::now().timestamp();
        self.l1.insert(key.to_string(), L1Entry { value: v as u64, ts: now, hits: 1 });
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
    async fn store_refresh_token(&self, user_id: &str, tenant_id: &str, token: &str, ttl_seconds: u64) -> Result<()> {
        let mut conn = self.conn.clone();
        let token_hash = hash_refresh_token(token)?;
        // Key: refresh_token:{hash}, Value: {tenant_id}:{user_id}
        // Also keep a way to revoke all tokens for a user: user_tokens:{user_id} -> set of hashes
        let token_key = format!("refresh_token:{}", token_hash);
        let user_tokens_key = format!("user_tokens:{}", user_id);
        let token_value = format!("{}:{}", tenant_id, user_id);
        
        let _: () = conn.set_ex(&token_key, token_value, ttl_seconds).await?;
        let _: () = conn.sadd(&user_tokens_key, token_hash).await?;
        let _: () = conn.expire(&user_tokens_key, ttl_seconds as i64).await?;
        
        Ok(())
    }

    async fn get_user_id_by_refresh_token(&self, token: &str) -> Result<Option<String>> {
        let mut conn = self.conn.clone();
        let token_hash = hash_refresh_token(token)?;
        let token_key = format!("refresh_token:{}", token_hash);
        let user_id: Option<String> = conn.get(token_key).await?;
        Ok(user_id)
    }

    async fn revoke_refresh_token(&self, token: &str) -> Result<()> {
        let mut conn = self.conn.clone();
        let token_hash = hash_refresh_token(token)?;
        if let Some(user_id) = self.get_user_id_by_refresh_token(token).await? {
            let token_key = format!("refresh_token:{}", token_hash);
            let user_id = user_id.split(':').next_back().unwrap_or(&user_id).to_string();
            let user_tokens_key = format!("user_tokens:{}", user_id);
            let _: () = conn.del(token_key).await?;
            let _: () = conn.srem(user_tokens_key, token_hash).await?;
        }
        Ok(())
    }

    async fn revoke_all_user_tokens(&self, user_id: &str) -> Result<()> {
        let mut conn = self.conn.clone();
        let user_tokens_key = format!("user_tokens:{}", user_id);
        let token_hashes: Vec<String> = conn.smembers(&user_tokens_key).await?;
        
        for token_hash in token_hashes {
            let token_key = format!("refresh_token:{}", token_hash);
            let _: () = conn.del(token_key).await?;
        }
        let _: () = conn.del(user_tokens_key).await?;
        
        Ok(())
    }

    async fn delete_key(&self, key: &str) -> Result<()> {
        let mut conn = self.conn.clone();
        let _: () = conn.del(key).await?;
        Ok(())
    }

    async fn expire_key(&self, key: &str, ttl_seconds: u64) -> Result<()> {
        let mut conn = self.conn.clone();
        let _: () = conn.expire(key, ttl_seconds as i64).await?;
        Ok(())
    }

    async fn zadd(&self, key: &str, member: &str, score: i64) -> Result<()> {
        let mut conn = self.conn.clone();
        let _: () = conn.zadd(key, member, score).await?;
        Ok(())
    }

    async fn zcard(&self, key: &str) -> Result<u64> {
        let mut conn = self.conn.clone();
        let count: u64 = conn.zcard(key).await?;
        Ok(count)
    }

    async fn zpopmin(&self, key: &str) -> Result<Option<String>> {
        let mut conn = self.conn.clone();
        let result: Option<(String, f64)> = redis::cmd("ZPOPMIN")
            .arg(key)
            .query_async(&mut conn)
            .await?;
        Ok(result.map(|(member, _score)| member))
    }

    async fn zrem(&self, key: &str, member: &str) -> Result<()> {
        let mut conn = self.conn.clone();
        let _: () = conn.zrem(key, member).await?;
        Ok(())
    }

    async fn set_string(&self, key: &str, value: &str, expiry_seconds: Option<u64>) -> Result<()> {
        let mut conn = self.conn.clone();
        let _: () = conn.set(key, value).await?;
        if let Some(exp) = expiry_seconds {
            let _: () = conn.expire(key, exp as i64).await?;
        }
        Ok(())
    }

    async fn get_string(&self, key: &str) -> Result<Option<String>> {
        let mut conn = self.conn.clone();
        let value: Option<String> = conn.get(key).await?;
        Ok(value)
    }
}

impl RedisCache {
    pub async fn new(redis_url: &str) -> Result<Self> {
        info!("🗄️  Connecting to Redis...");
        
        let client = Client::open(redis_url)?;
        let conn = ConnectionManager::new(client).await?;
        
        info!("✅ Connected to Redis");
        Ok(Self { conn, l1: Arc::new(DashMap::new()), refresh_locks: Arc::new(DashMap::new()) })
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
        let now = Utc::now().timestamp();
        self.l1.insert(keys[0].to_string(), L1Entry { value: ta as u64, ts: now, hits: 1 });
        self.l1.insert(keys[1].to_string(), L1Entry { value: aa as u64, ts: now, hits: 1 });
        self.l1.insert(keys[2].to_string(), L1Entry { value: ca as u64, ts: now, hits: 1 });

        Ok((ta as u32, aa as u32, ca as u32))
    }

    // Increment a counter by `delta` atomically and set expiry. Returns the new value.
    pub async fn incr_by(&self, key: &str, delta: u64, expiry_seconds: u64) -> Result<u32> {
        let mut conn = self.conn.clone();
        let new: i64 = conn.incr(key, delta as i64).await?;
        let _: () = conn.expire(key, expiry_seconds as i64).await?;
        let new_u = if new < 0 { 0 } else { new as u32 };
        let now = Utc::now().timestamp();
        self.l1.insert(key.to_string(), L1Entry { value: new as u64, ts: now, hits: 1 });
        Ok(new_u)
    }

    /// Refresh a single key from Redis and update L1. Uses per-key async locks to avoid stampedes.
    pub async fn refresh_key(&self, key: &str) -> Result<()> {
        // obtain or create lock
        let lock = match self.refresh_locks.get(key) {
            Some(l) => l.value().clone(),
            None => {
                let m = Arc::new(AsyncMutex::new(()));
                self.refresh_locks.insert(key.to_string(), m.clone());
                m
            }
        };

        let _guard = lock.lock().await;

        // fetch value from redis
        let mut conn = self.conn.clone();
        let val: Option<u64> = conn.get(key).await?;
        if let Some(v) = val {
            let now = Utc::now().timestamp();
            // preserve previous hits if present
            let hits = self.l1.get(key).map(|e| e.value().hits).unwrap_or(1);
            self.l1.insert(key.to_string(), L1Entry { value: v as u64, ts: now, hits });
        }
        Ok(())
    }

    /// Start a background task that evicts L1 entries older than `max_age_secs`.
    /// Returns a JoinHandle you can await or abort on shutdown.
    /// Start maintenance loop. Performs:
    /// - periodic eviction of entries older than `max_age_secs`
    /// - refresh of top `refresh_top_n` hot keys from Redis
    /// - interval controlled by `interval_secs`
    pub fn start_l1_maintenance(&self, interval_secs: u64, max_age_secs: u64, refresh_if_older_secs: u64, refresh_top_n: usize) -> tokio::task::JoinHandle<()> {
        let cache = self.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(interval_secs)).await;
                let now = Utc::now().timestamp();

                // Evict cold entries
                let keys: Vec<String> = cache.l1.iter().map(|kv| kv.key().clone()).collect();
                for k in keys.iter() {
                    if let Some(v) = cache.l1.get(k) {
                        if now - v.value().ts > max_age_secs as i64 {
                            cache.l1.remove(k);
                        }
                    }
                }

                // Collect top-N hottest keys by hits
                let mut items: Vec<(String,u64)> = cache.l1.iter().map(|kv| (kv.key().clone(), kv.value().hits)).collect();
                items.sort_by(|a,b| b.1.cmp(&a.1));
                let top = items.into_iter().take(refresh_top_n).map(|(k,_)| k).collect::<Vec<_>>();

                // Refresh hot keys if they are older than refresh_if_older_secs
                for k in top {
                    if let Some(e) = cache.l1.get(&k) {
                        if now - e.value().ts > refresh_if_older_secs as i64 {
                            let c = cache.clone();
                            let kk = k.clone();
                            tokio::spawn(async move {
                                let _ = c.refresh_key(&kk).await;
                            });
                        }
                    }
                }
            }
        })
    }
}
