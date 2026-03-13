use async_trait::async_trait;
use crate::types::{Log, Alert};

#[async_trait]
#[allow(dead_code)]
pub trait Rule: Send + Sync {
    fn name(&self) -> &str;
    fn id(&self) -> &str;
    /// Evaluate a log entry. Returns `Ok(Some(alert))` if rule triggers,
    /// `Ok(None)` if rule passed, or `Err` on error.
    async fn evaluate(&self, log: &Log) -> anyhow::Result<Option<Alert>>;
}

pub mod brute_force;
pub mod port_scan;
pub mod malware;