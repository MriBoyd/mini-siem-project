use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::types::{Log, Alert};
use crate::db::RedisCache;
use super::Rule;

#[allow(dead_code)]
pub struct PortScanRule {
    id: String,
    name: String,
    port_threshold: u32,
    window_seconds: i64,
    redis: Arc<Mutex<RedisCache>>,
}

impl PortScanRule {
    pub fn new(
        id: String,
        name: String,
        port_threshold: u32,
        window_seconds: i64,
        redis: Arc<Mutex<RedisCache>>,
    ) -> Self {
        Self { id, name, port_threshold, window_seconds, redis }
    }
}

#[async_trait]
impl Rule for PortScanRule {
    fn name(&self) -> &str { &self.name }
    fn id(&self) -> &str { &self.id }
    async fn evaluate(&self, _log: &Log) -> anyhow::Result<Option<Alert>> {
        // placeholder implementation
        Ok(None)
    }
}
