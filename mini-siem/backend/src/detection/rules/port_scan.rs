use async_trait::async_trait;
use std::sync::Arc;

use crate::types::{Log, Alert};
use crate::db::Cache;
use super::Rule;

#[allow(dead_code)]
pub struct PortScanRule {
    id: String,
    name: String,
    port_threshold: u32,
    window_seconds: i64,
    redis: Arc<dyn Cache>,
}

impl PortScanRule {
    pub fn new(
        id: String,
        name: String,
        port_threshold: u32,
        window_seconds: i64,
        redis: Arc<dyn Cache>,
    ) -> Self {
        Self { id, name, port_threshold, window_seconds, redis }
    }
}

#[async_trait]
impl Rule for PortScanRule {
    fn name(&self) -> &str { &self.name }
    fn id(&self) -> &str { &self.id }
    fn log_types(&self) -> Vec<crate::types::LogTag> {
        vec![crate::types::LogTag::Network]
    }
    async fn evaluate(&self, _log: &Log) -> anyhow::Result<Option<Alert>> {
        // placeholder implementation
        Ok(None)
    }
}
