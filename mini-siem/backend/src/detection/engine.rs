use tokio::sync::broadcast;
use tracing::{info, warn, error};
use std::sync::Arc;
use arc_swap::ArcSwap;
use futures_util::stream::{self, StreamExt};

use crate::types::{Log, Alert};
use crate::queue::kafka::KafkaQueue;
use crate::db::{PostgresDb, RedisCache};
use crate::db::cache::Cache;
use crate::response::engine::ResponseEngine;
use super::rules::{
    Rule, 
    brute_force::BruteForceRule,
    port_scan::PortScanRule,
    malware::MalwareDetectionRule,
};

    pub struct DetectionEngine {
    rules: ArcSwap<Vec<Arc<dyn Rule + Send + Sync>>>,
    alert_tx: broadcast::Sender<Alert>,
    stats_tx: broadcast::Sender<crate::types::DashboardStats>,
    redis: RedisCache,
    db: Arc<PostgresDb>,
    response_engine: Arc<ResponseEngine>,
    kafka: Arc<KafkaQueue>,
}

impl DetectionEngine {
    pub async fn new(
        alert_tx: broadcast::Sender<Alert>,
        stats_tx: broadcast::Sender<crate::types::DashboardStats>,
        redis: RedisCache,
        db: Arc<PostgresDb>,
        response_engine: Arc<ResponseEngine>,
        kafka: Arc<KafkaQueue>,
    ) -> Self {
        let engine = Self {
            rules: ArcSwap::from_pointee(Vec::new()),
            alert_tx,
            stats_tx,
            redis,
            db,
            response_engine,
            kafka,
        };
        
        // Initial rules load
        if let Err(e) = engine.reload_rules().await {
            error!("Failed to load initial rules: {}", e);
        }
        
        engine
    }

    pub async fn reload_rules(&self) -> anyhow::Result<()> {
        let db_rules = self.db.get_enabled_rules().await?;
        let mut new_rules: Vec<Arc<dyn Rule + Send + Sync>> = Vec::new();

        for dr in db_rules {
            match dr.rule_type.as_str() {
                "brute_force" => {
                    new_rules.push(Arc::new(BruteForceRule::new(
                        dr.id.to_string(),
                        dr.name,
                        dr.threshold.unwrap_or(5) as u32,
                        dr.window_seconds.unwrap_or(300) as i64,
                        Arc::new(self.redis.clone()),
                    )));
                }
                "port_scan" => {
                    new_rules.push(Arc::new(PortScanRule::new(
                        dr.id.to_string(),
                        dr.name,
                        dr.threshold.unwrap_or(20) as u32,
                        dr.window_seconds.unwrap_or(60) as i64,
                        Arc::new(self.redis.clone()),
                    )));
                }
                "malware" => {
                    new_rules.push(Arc::new(MalwareDetectionRule::new(
                        dr.id.to_string(),
                        dr.name,
                        Arc::new(self.redis.clone()),
                    )));
                }
                _ => warn!("Unknown rule type: {}", dr.rule_type),
            }
        }

        let count = new_rules.len();
        self.rules.store(Arc::new(new_rules));
        
        info!("🧠 Detection engine reloaded with {} rules", count);
        Ok(())
    }
    
    pub async fn process_log(&self, log: Log) {
        let mut alerts_to_process = Vec::new();
        
        // Check each rule concurrently
        {
            let rules = self.rules.load();

            let mut eval_futures = Vec::with_capacity(rules.len());
            for rule in rules.iter() {
                let name = rule.name().to_string();
                let rule_arc = rule.clone();
                let log_clone = log.clone();
                eval_futures.push(async move { (name, rule_arc.evaluate(&log_clone).await) });
            }

            let results = stream::iter(eval_futures)
                .buffer_unordered(10)
                .collect::<Vec<_>>()
                .await;

            for (rule_name, result) in results.into_iter() {
                match result {
                    Ok(Some(alert)) => {
                        warn!("🚨 Rule triggered: {} - {}", rule_name, alert.description);
                        alerts_to_process.push(alert);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        error!("Rule evaluation error ({}): {}", rule_name, e);
                    }
                }
            }
        }
        
        // Handle alerts: enqueue to Kafka for async processing by workers.
        for alert in alerts_to_process {
            match self.kafka.send_alert(&alert).await {
                Ok(_) => {
                    // also broadcast lightweight notification for real-time UIs
                    let _ = self.alert_tx.send(alert.clone());
                }
                Err(e) => {
                    error!("Failed to enqueue alert to Kafka: {}. Falling back to immediate processing.", e);
                    // Fallback: persist immediately and trigger response engine to avoid data loss
                    if let Err(e) = self.db.create_alert(&alert).await {
                        error!("Failed to save alert to database: {}", e);
                    }
                    self.response_engine.handle_alert(&alert).await;
                    if self.alert_tx.send(alert.clone()).is_err() {
                        warn!("Alert channel closed");
                    }
                }
            }
        }
    }
    
    #[allow(dead_code)]
    pub async fn get_stats(&self) -> serde_json::Value {
        // No lock needed for redis anymore as it's cloneable and internal implementation handles it
        let rules_count = self.rules.load().len();
        
        // Get some Redis stats
        let mut stats = serde_json::Map::new();
        
        // This would be expanded with real metrics
        stats.insert("rules_loaded".to_string(), rules_count.into());
        
        serde_json::Value::Object(stats)
    }
}
