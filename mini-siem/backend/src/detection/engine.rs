use tokio::sync::broadcast;
use tracing::{info, warn, error};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::types::{Log, Alert};
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
    rules: Arc<RwLock<Vec<Box<dyn Rule + Send + Sync>>>>,
    alert_tx: broadcast::Sender<Alert>,
    stats_tx: broadcast::Sender<crate::types::DashboardStats>,
    redis: RedisCache,
    db: Arc<PostgresDb>,
    response_engine: Arc<ResponseEngine>,
}

impl DetectionEngine {
    pub async fn new(
        alert_tx: broadcast::Sender<Alert>,
        stats_tx: broadcast::Sender<crate::types::DashboardStats>,
        redis: RedisCache,
        db: Arc<PostgresDb>,
        response_engine: Arc<ResponseEngine>,
    ) -> Self {
        let engine = Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            alert_tx,
            stats_tx,
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

                        if let Err(e) = self.db.update_alert(existing, Some(self.redis.clone())).await {
                            error!("Failed to update alert in database: {}", e);
                        }

                        // Send updated alert to channel
                        if self.alert_tx.send(existing.clone()).is_err() {
                            warn!("Alert channel closed");
                        }
                        // For an updated alert we do not change total_alerts, but events_count changed.
                        // Publish aggregated stats by reading Redis counters (fallback to DB and seed Redis)
                        let tl: Option<u32> = self.redis.get_counter("siem:stats:total_logs").await.ok().flatten();
                        let ta: Option<u32> = self.redis.get_counter("siem:stats:total_alerts").await.ok().flatten();
                        let aa: Option<u32> = self.redis.get_counter("siem:stats:active_alerts").await.ok().flatten();
                        let ca: Option<u32> = self.redis.get_counter("siem:stats:critical_alerts").await.ok().flatten();
                        if let (Some(tl), Some(ta), Some(aa), Some(ca)) = (tl, ta, aa, ca) {
                            let stats = crate::types::DashboardStats {
                                total_logs: tl as i64,
                                total_alerts: ta as i64,
                                active_alerts: aa as i64,
                                critical_alerts: ca as i64,
                            };
                            let _ = self.stats_tx.send(stats);
                        } else if let Ok((tl, ta, aa, ca)) = self.db.get_stats().await {
                            let stats = crate::types::DashboardStats::from((tl, ta, aa, ca));
                            let _ = self.stats_tx.send(stats.clone());
                            let _ = self.redis.set_counter("siem:stats:total_logs", tl as u64, Some(86400)).await;
                            let _ = self.redis.set_counter("siem:stats:total_alerts", ta as u64, Some(86400)).await;
                            let _ = self.redis.set_counter("siem:stats:active_alerts", aa as u64, Some(86400)).await;
                            let _ = self.redis.set_counter("siem:stats:critical_alerts", ca as u64, Some(86400)).await;
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
                        // Increment Redis counters for alerts
                        let _ = self.redis.increment_counter("siem:stats:total_alerts", 86400).await;
                        let _ = self.redis.increment_counter("siem:stats:active_alerts", 86400).await;
                        if alert.severity == crate::types::AlertSeverity::Critical {
                            let _ = self.redis.increment_counter("siem:stats:critical_alerts", 86400).await;
                        }
                        // Publish aggregated stats by reading Redis counters (fallback to DB and seed Redis)
                        let tl: Option<u32> = self.redis.get_counter("siem:stats:total_logs").await.ok().flatten();
                        let ta: Option<u32> = self.redis.get_counter("siem:stats:total_alerts").await.ok().flatten();
                        let aa: Option<u32> = self.redis.get_counter("siem:stats:active_alerts").await.ok().flatten();
                        let ca: Option<u32> = self.redis.get_counter("siem:stats:critical_alerts").await.ok().flatten();
                        if let (Some(tl), Some(ta), Some(aa), Some(ca)) = (tl, ta, aa, ca) {
                            let stats = crate::types::DashboardStats {
                                total_logs: tl as i64,
                                total_alerts: ta as i64,
                                active_alerts: aa as i64,
                                critical_alerts: ca as i64,
                            };
                            let _ = self.stats_tx.send(stats);
                        } else if let Ok((tl, ta, aa, ca)) = self.db.get_stats().await {
                            let stats = crate::types::DashboardStats::from((tl, ta, aa, ca));
                            let _ = self.stats_tx.send(stats.clone());
                            let _ = self.redis.set_counter("siem:stats:total_logs", tl as u64, Some(86400)).await;
                            let _ = self.redis.set_counter("siem:stats:total_alerts", ta as u64, Some(86400)).await;
                            let _ = self.redis.set_counter("siem:stats:active_alerts", aa as u64, Some(86400)).await;
                            let _ = self.redis.set_counter("siem:stats:critical_alerts", ca as u64, Some(86400)).await;
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
