use tokio::sync::{mpsc, broadcast};
use tracing::{info, warn, error};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::types::{Log, Alert};
use crate::db::{PostgresDb, RedisCache};
use crate::response::engine::ResponseEngine;
use super::rules::{
    Rule, 
    brute_force::BruteForceRule,
    port_scan::PortScanRule,
    malware::MalwareDetectionRule,
};

pub struct DetectionEngine {
    rules: Arc<RwLock<Vec<Box<dyn Rule + Send + Sync>>>>,
    alert_tx: broadcast::Sender<Alert>,
    redis: RedisCache,
    db: Arc<PostgresDb>,
    response_engine: Arc<ResponseEngine>,
}

impl DetectionEngine {
    pub async fn new(
        alert_tx: broadcast::Sender<Alert>,
        redis: RedisCache,
        db: Arc<PostgresDb>,
        response_engine: Arc<ResponseEngine>,
    ) -> Self {
        let engine = Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            alert_tx,
            redis,
            db,
            response_engine,
        };
        
        // Initial rules load
        if let Err(e) = engine.reload_rules().await {
            error!("Failed to load initial rules: {}", e);
        }
        
        engine
    }

    pub async fn reload_rules(&self) -> anyhow::Result<()> {
        let db_rules = self.db.get_enabled_rules().await?;
        let mut new_rules: Vec<Box<dyn Rule + Send + Sync>> = Vec::new();

        for dr in db_rules {
            match dr.rule_type.as_str() {
                "brute_force" => {
                    new_rules.push(Box::new(BruteForceRule::new(
                        dr.id.to_string(),
                        dr.name,
                        dr.threshold.unwrap_or(5) as u32,
                        dr.window_seconds.unwrap_or(300) as i64,
                        Arc::new(self.redis.clone()),
                    )));
                }
                "port_scan" => {
                    new_rules.push(Box::new(PortScanRule::new(
                        dr.id.to_string(),
                        dr.name,
                        dr.threshold.unwrap_or(20) as u32,
                        dr.window_seconds.unwrap_or(60) as i64,
                        Arc::new(self.redis.clone()),
                    )));
                }
                "malware" => {
                    new_rules.push(Box::new(MalwareDetectionRule::new(
                        dr.id.to_string(),
                        dr.name,
                        Arc::new(self.redis.clone()),
                    )));
                }
                _ => warn!("Unknown rule type: {}", dr.rule_type),
            }
        }

        let count = new_rules.len();
        let mut rules_lock = self.rules.write().await;
        *rules_lock = new_rules;
        
        info!("🧠 Detection engine reloaded with {} rules", count);
        Ok(())
    }
    
    pub async fn process_log(&self, log: Log) {
        let mut alerts_to_process = Vec::new();
        
        // Check each rule concurrently
        {
            let rules = self.rules.read().await;
            
            let mut eval_futures = Vec::with_capacity(rules.len());
            for rule in rules.iter() {
                eval_futures.push(rule.evaluate(&log));
            }

            let results = futures_util::future::join_all(eval_futures).await;

            for (idx, result) in results.into_iter().enumerate() {
                match result {
                    Ok(Some(alert)) => {
                        let rule_name = rules[idx].name();
                        warn!("🚨 Rule triggered: {} - {}", rule_name, alert.description);
                        alerts_to_process.push(alert);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        let rule_name = rules[idx].name();
                        error!("Rule evaluation error ({}): {}", rule_name, e);
                    }
                }
            }
        }
        
        // Handle alerts
        for alert in alerts_to_process {
            // Check for existing open alert from same IP
            match self.db.get_open_alerts_by_ip(&alert.source_ip).await {
                Ok(mut existing_alerts) => {
                    if let Some(existing) = existing_alerts.first_mut() {
                        // Update existing alert
                        existing.last_seen = alert.last_seen;
                        existing.events_count += alert.events_count;

                        if let Err(e) = self.db.update_alert(existing).await {
                            error!("Failed to update alert in database: {}", e);
                        }

                        // Send updated alert to channel
                        if self.alert_tx.send(existing.clone()).is_err() {
                            warn!("Alert channel closed");
                        }
                    } else {
                        // Save new alert
                        if let Err(e) = self.db.create_alert(&alert).await {
                            error!("Failed to save alert to database: {}", e);
                        }

                        // Trigger Response Engine (SOAR)
                        self.response_engine.handle_alert(&alert).await;

                        // Send new alert to channel
                        if self.alert_tx.send(alert.clone()).is_err() {
                            warn!("Alert channel closed");
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to check existing alerts: {}", e);
                }
            }
        }
    }
    
    #[allow(dead_code)]
    pub async fn get_stats(&self) -> serde_json::Value {
        // No lock needed for redis anymore as it's cloneable and internal implementation handles it
        let rules_count = self.rules.read().await.len();
        
        // Get some Redis stats
        let mut stats = serde_json::Map::new();
        
        // This would be expanded with real metrics
        stats.insert("rules_loaded".to_string(), rules_count.into());
        
        serde_json::Value::Object(stats)
    }
}
