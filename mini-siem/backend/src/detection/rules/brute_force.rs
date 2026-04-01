use async_trait::async_trait;
use std::sync::Arc;

use crate::types::{Log, Alert, AlertSeverity};
use crate::db::Cache;
use super::Rule;

pub struct BruteForceRule {
    tenant_id: String,
    name: String,
    id: String,
    threshold: u32,
    window_seconds: i64,
    redis: Arc<dyn Cache>,
}

impl BruteForceRule {
    pub fn new(
        tenant_id: String,
        id: String,
        name: String,
        threshold: u32,
        window_seconds: i64,
        redis: Arc<dyn Cache>,
    ) -> Self {
        Self {
            tenant_id,
            name,
            id,
            threshold,
            window_seconds,
            redis,
        }
    }
}

#[async_trait]
impl Rule for BruteForceRule {
    fn name(&self) -> &str {
        &self.name
    }
    
    fn id(&self) -> &str {
        &self.id
    }

    fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
    fn log_types(&self) -> Vec<crate::types::LogTag> {
        vec![crate::types::LogTag::Auth]
    }
    
    async fn evaluate(&self, log: &Log) -> anyhow::Result<Option<Alert>> {
        // Only check failed logins
        if !log.is_failed_login() {
            return Ok(None);
        }
        
        let key = log.source_ip.clone();
        
        // increment counter in redis with expiry equal to window
        let count = self.redis.increment_counter(&key, self.window_seconds as u64).await?;
        if count >= self.threshold {
            Ok(Some(Alert::new(
                log.tenant_id.clone(),
                self.id.clone(),
                self.name.clone(),
                AlertSeverity::High,
                format!(
                    "Possible brute force attack from {}: {} failed attempts",
                    log.source_ip, count
                ),
                log.source_ip.clone(),
                vec![log.clone()],
            )))
        } else {
            Ok(None)
        }
    }
}