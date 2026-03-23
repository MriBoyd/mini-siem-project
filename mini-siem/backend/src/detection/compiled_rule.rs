use crate::types::{Log, Alert, LogTag};
use anyhow::Result;
use super::rules::Rule;

use super::rules::{brute_force::BruteForceRule, port_scan::PortScanRule, malware::MalwareDetectionRule};

pub enum CompiledRule {
    BruteForce(BruteForceRule),
    PortScan(PortScanRule),
    Malware(MalwareDetectionRule),
}

impl CompiledRule {
    pub fn name(&self) -> String {
        match self {
            CompiledRule::BruteForce(r) => r.name().to_string(),
            CompiledRule::PortScan(r) => r.name().to_string(),
            CompiledRule::Malware(r) => r.name().to_string(),
        }
    }

    pub fn log_types(&self) -> Vec<LogTag> {
        match self {
            CompiledRule::BruteForce(r) => r.log_types(),
            CompiledRule::PortScan(r) => r.log_types(),
            CompiledRule::Malware(r) => r.log_types(),
        }
    }

    pub async fn evaluate(&self, log: &Log) -> Result<Option<Alert>> {
        match self {
            CompiledRule::BruteForce(r) => r.evaluate(log).await,
            CompiledRule::PortScan(r) => r.evaluate(log).await,
            CompiledRule::Malware(r) => r.evaluate(log).await,
        }
    }
}
