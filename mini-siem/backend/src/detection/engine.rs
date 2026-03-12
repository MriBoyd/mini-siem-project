use tokio::sync::mpsc;
use tracing::{info, warn, error};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::types::{Log, Alert};
use crate::db::{PostgresDb, RedisCache};
use super::rules::{
    Rule, 
    brute_force::BruteForceRule,
    port_scan::PortScanRule,
    malware::MalwareDetectionRule,
};

pub struct DetectionEngine {
    rules: Vec<Box<dyn Rule + Send + Sync>>,
    alert_tx: mpsc::Sender<Alert>,
    redis: Arc<Mutex<RedisCache>>,
    db: Arc<PostgresDb>,
}

impl DetectionEngine {
    pub async fn new(
        alert_tx: mpsc::Sender<Alert>,
        redis: RedisCache,
        db: Arc<PostgresDb>,
    ) -> Self {
        let redis = Arc::new(Mutex::new(redis));
        // db is already an Arc
        
        let rules: Vec<Box<dyn Rule + Send + Sync>> = vec![
            Box::new(BruteForceRule::new(
                "rule_001".to_string(),
                "SSH Brute Force Detection".to_string(),
                5,      // threshold
                300,    // 5 minute window
                redis.clone(),
            )),
            Box::new(PortScanRule::new(
                "rule_002".to_string(),
                "Port Scan Detection".to_string(),
                20,     // ports threshold
                60,     // 1 minute window
                redis.clone(),
            )),
            Box::new(MalwareDetectionRule::new(
                "rule_003".to_string(),
                "Malware Communication Detection".to_string(),
                redis.clone(),
            )),
        ];
        
        info!("🧠 Detection engine initialized with {} rules", rules.len());
        
        Self {
            rules,
            alert_tx,
            redis,
            db,
        }
    }
    
    pub async fn process_log(&self, log: Log) {
        let mut alerts = Vec::new();
        
        // Check each rule
        for rule in &self.rules {
            match rule.evaluate(&log).await {
                Ok(Some(alert)) => {
                    warn!("🚨 Rule triggered: {} - {}", rule.name(), alert.description);
                    alerts.push(alert);
                }
                Ok(None) => {}
                Err(e) => {
                    error!("Rule evaluation error: {}", e);
                }
            }
        }
        
        // Handle alerts
        for alert in alerts {
            // Check for existing open alert from same IP
            match self.db.get_open_alerts_by_ip(&alert.source_ip).await {
                Ok(mut existing_alerts) => {
                    if let Some(existing) = existing_alerts.first_mut() {
                        // Update existing alert
                        existing.last_seen = alert.last_seen;
                        existing.events_count += alert.events_count;
                        existing.events.extend(alert.events);
                        
                        if let Err(e) = self.db.update_alert(existing).await {
                            error!("Failed to update alert in database: {}", e);
                        }
                        
                        // Send to channel
                        if self.alert_tx.send(existing.clone()).await.is_err() {
                            warn!("Alert channel closed");
                        }
                    } else {
                        // Save new alert
                        if let Err(e) = self.db.create_alert(&alert).await {
                            error!("Failed to save alert to database: {}", e);
                        }
                        
                        // Send to channel
                        if self.alert_tx.send(alert).await.is_err() {
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
    
    pub async fn get_stats(&self) -> serde_json::Value {
        let mut redis = self.redis.lock().await;
        
        // Get some Redis stats
        let mut stats = serde_json::Map::new();
        
        // This would be expanded with real metrics
        stats.insert("rules_loaded".to_string(), self.rules.len().into());
        
        serde_json::Value::Object(stats)
    }
}