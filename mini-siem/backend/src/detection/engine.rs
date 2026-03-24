use tokio::sync::{broadcast, mpsc};
use tracing::{info, warn, error};
use std::sync::Arc;
use arc_swap::ArcSwap;
use rustc_hash::FxHashMap as HashMap;
use futures_util::stream::{self, StreamExt};
use smallvec::SmallVec;

use crate::types::{Log, Alert, AlertSeverity};
use crate::types::LogTag;
use crate::queue::kafka::KafkaQueue;
use crate::db::{PostgresDb, RedisCache};
use crate::response::engine::ResponseEngine;
use super::compiled_rule::CompiledRule;
use super::rules::{
    brute_force::BruteForceRule,
    port_scan::PortScanRule,
    malware::MalwareDetectionRule,
    generic::GenericRule,
};
use crate::detection::evaluator::RuleCondition;

    pub struct DetectionEngine {
    // Map of log_type/tag -> list of precompiled rules (lock-free reads)
    rules: ArcSwap<HashMap<LogTag, Vec<Arc<CompiledRule>>>>,
    alert_tx: broadcast::Sender<Alert>,
    stats_tx: broadcast::Sender<crate::types::DashboardStats>,
    redis: RedisCache,
    db: Arc<PostgresDb>,
    response_engine: Arc<ResponseEngine>,
    kafka: Arc<KafkaQueue>,
    // Local in-memory aggregated stats to avoid Redis roundtrips on every alert/log
    local_stats: Arc<LocalStats>,
    // notify channel to avoid spawning tasks per-alert for stats broadcasting
    stats_notify_tx: mpsc::Sender<()>,
}

use std::sync::atomic::{AtomicU64, Ordering};

pub struct LocalStats {
    pub total_logs: AtomicU64,
    pub total_alerts: AtomicU64,
    pub active_alerts: AtomicU64,
    pub critical_alerts: AtomicU64,
}

impl LocalStats {
    pub fn new() -> Self {
        Self {
            total_logs: AtomicU64::new(0),
            total_alerts: AtomicU64::new(0),
            active_alerts: AtomicU64::new(0),
            critical_alerts: AtomicU64::new(0),
        }
    }

    pub fn incr_log(&self) {
        self.total_logs.fetch_add(1, Ordering::Relaxed);
    }

    pub fn incr_alert(&self, is_critical: bool) {
        self.total_alerts.fetch_add(1, Ordering::Relaxed);
        self.active_alerts.fetch_add(1, Ordering::Relaxed);
        if is_critical {
            self.critical_alerts.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Atomically fetch and reset counters. Returns (tl, ta, aa, ca).
    pub fn take_and_reset(&self) -> (u64,u64,u64,u64) {
        let tl = self.total_logs.swap(0, Ordering::Relaxed);
        let ta = self.total_alerts.swap(0, Ordering::Relaxed);
        let aa = self.active_alerts.swap(0, Ordering::Relaxed);
        let ca = self.critical_alerts.swap(0, Ordering::Relaxed);
        (tl, ta, aa, ca)
    }
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
        // create stats notify channel
        let (stats_notify_tx, stats_notify_rx) = mpsc::channel::<()>(1024);

        let engine = Self {
            rules: ArcSwap::from_pointee(HashMap::default()),
            alert_tx,
            stats_tx,
            redis,
            db,
            response_engine,
            kafka,
            local_stats: Arc::new(LocalStats::new()),
            stats_notify_tx,
        };
        
        // Initial rules load
        if let Err(e) = engine.reload_rules().await {
            error!("Failed to load initial rules: {}", e);
        }

        // Spawn background task to flush local stats to Redis periodically (every 1s).
        {
            let redis = engine.redis.clone();
            let stats = engine.local_stats.clone();
            tokio::spawn(async move {
                let flush_interval = tokio::time::Duration::from_secs(1);
                // expiry for stats in Redis (one week)
                let expiry = 60 * 60 * 24 * 7;
                loop {
                    tokio::time::sleep(flush_interval).await;
                    let (tl, ta, aa, ca) = stats.take_and_reset();
                    if tl > 0 {
                        let _ = redis.incr_by("siem:stats:total_logs", tl, expiry).await;
                    }
                    if ta > 0 {
                        let _ = redis.incr_by("siem:stats:total_alerts", ta, expiry).await;
                    }
                    if aa > 0 {
                        let _ = redis.incr_by("siem:stats:active_alerts", aa, expiry).await;
                    }
                    if ca > 0 {
                        let _ = redis.incr_by("siem:stats:critical_alerts", ca, expiry).await;
                    }
                }
            });
        }

        // Spawn a dedicated stats worker that listens for notifications from the hot path
        // and broadcasts a coalesced DashboardStats update to `stats_tx`.
        {
            let stats = engine.local_stats.clone();
            let stats_tx = engine.stats_tx.clone();
            tokio::spawn(async move {
                let mut rx = stats_notify_rx;
                loop {
                    // Wait for at least one notification
                    if rx.recv().await.is_none() {
                        // channel closed
                        break;
                    }

                    // Coalesce events for up to 100ms to avoid spamming broadcasts
                    let coalesce = tokio::time::sleep(tokio::time::Duration::from_millis(100));
                    tokio::pin!(coalesce);
                    tokio::select! {
                        _ = &mut coalesce => {},
                        _ = rx.recv() => {
                            // drained one more, continue waiting until timeout
                            let _ = tokio::time::sleep(tokio::time::Duration::from_millis(0)).await;
                        }
                    }

                    // Take a snapshot from local stats and broadcast
                    let tl = stats.total_logs.load(Ordering::Relaxed) as i64;
                    let ta = stats.total_alerts.load(Ordering::Relaxed) as i64;
                    let aa = stats.active_alerts.load(Ordering::Relaxed) as i64;
                    let ca = stats.critical_alerts.load(Ordering::Relaxed) as i64;

                    let snapshot = crate::types::DashboardStats {
                        total_logs: tl,
                        total_alerts: ta,
                        active_alerts: aa,
                        critical_alerts: ca,
                    };

                    let _ = stats_tx.send(snapshot);
                }
            });
        }
        
        engine
    }

    pub async fn reload_rules(&self) -> anyhow::Result<()> {
        let db_rules = self.db.get_enabled_rules().await?;
        let mut new_rules: HashMap<LogTag, Vec<Arc<CompiledRule>>> = HashMap::default();

        for dr in db_rules {
            match dr.rule_type.as_str() {
                "brute_force" => {
                    let concrete = BruteForceRule::new(
                        dr.id.to_string(),
                        dr.name,
                        dr.threshold.unwrap_or(5) as u32,
                        dr.window_seconds.unwrap_or(300) as i64,
                        Arc::new(self.redis.clone()),
                    );
                    let compiled = Arc::new(CompiledRule::BruteForce(concrete));
                    for lt in compiled.log_types() {
                        new_rules.entry(lt).or_default().push(compiled.clone());
                    }
                }
                "port_scan" => {
                    let concrete = PortScanRule::new(
                        dr.id.to_string(),
                        dr.name,
                        dr.threshold.unwrap_or(20) as u32,
                        dr.window_seconds.unwrap_or(60) as i64,
                        Arc::new(self.redis.clone()),
                    );
                    let compiled = Arc::new(CompiledRule::PortScan(concrete));
                    for lt in compiled.log_types() {
                        new_rules.entry(lt).or_default().push(compiled.clone());
                    }
                }
                "malware" => {
                    let concrete = MalwareDetectionRule::new(
                        dr.id.to_string(),
                        dr.name,
                        Arc::new(self.redis.clone()),
                    );
                    let compiled = Arc::new(CompiledRule::Malware(concrete));
                    for lt in compiled.log_types() {
                        new_rules.entry(lt).or_default().push(compiled.clone());
                    }
                }
                "generic" => {
                    if let Some(condition_val) = dr.condition {
                        match serde_json::from_value::<RuleCondition>(condition_val) {
                            Ok(condition) => {
                                let concrete = GenericRule::new(
                                    dr.id.to_string(),
                                    dr.name,
                                    dr.severity,
                                    condition,
                                );
                                let compiled = Arc::new(CompiledRule::Generic(concrete));
                                for lt in compiled.log_types() {
                                    new_rules.entry(lt).or_default().push(compiled.clone());
                                }
                            }
                            Err(e) => error!("Failed to parse condition for generic rule {}: {}", dr.name, e),
                        }
                    } else {
                        warn!("Generic rule {} has no condition", dr.name);
                    }
                }
                _ => warn!("Unknown rule type: {}", dr.rule_type),
            }
        }

        // count total rules
        let count: usize = new_rules.values().map(|v| v.len()).sum();
        self.rules.store(Arc::new(new_rules));
        
        info!("🧠 Detection engine reloaded with {} rules", count);
        Ok(())
    }
    
    pub async fn process_log(&self, log: Arc<Log>) {
        let mut alerts_to_process = Vec::new();
        // Increment local total_logs counter for every processed log (hot path).
        self.local_stats.incr_log();
        
        // Check each rule concurrently
        {
            // start processing timer
            let proc_start = std::time::Instant::now();
            // Determine relevant rule types/tags for this log to avoid evaluating all rules.
            let rules_map = self.rules.load();
            let mut candidate_rules: SmallVec<[Arc<CompiledRule>; 8]> = SmallVec::new();

            // Infer tags from the log (small, fast heuristics). Rules declare which tags they
            // handle via `log_types()` and were indexed by those tags at reload time.
            let mut tags: Vec<LogTag> = Vec::new();
            if log.is_failed_login() || log.event_type.contains("auth") || log.event_type.contains("login") {
                tags.push(LogTag::Auth);
            }
            if log.event_type.contains("network") || log.event_type.contains("port") || log.service.as_deref().unwrap_or("").contains("ssh") {
                tags.push(LogTag::Network);
            }
            if log.message.contains("http") || log.message.contains('.') || log.message.contains("powershell") || log.message.contains("wget") {
                tags.push(LogTag::Malware);
            }

            // Collect candidate rules from the index
            for tag in tags.iter() {
                if let Some(v) = rules_map.get(tag) {
                    candidate_rules.extend(v.iter().cloned());
                }
            }

            // Fallback: if no candidates found, run rules indexed under "malware" (lightweight) if present
            if candidate_rules.is_empty() {
                if let Some(v) = rules_map.get(&LogTag::Malware) {
                    candidate_rules.extend(v.iter().cloned());
                }
            }

            let mut eval_futures = Vec::with_capacity(candidate_rules.len());
            for rule in candidate_rules.iter() {
                let name = rule.name();
                let rule_arc = rule.clone();
                let log_arc = log.clone();
                eval_futures.push(async move { (name, rule_arc.evaluate(&*log_arc).await) });
            }

            let results = stream::iter(eval_futures)
                .buffer_unordered(10)
                .collect::<Vec<_>>()
                .await;

                    for (rule_name, result) in results.into_iter() {
                match result {
                    Ok(Some(alert)) => {
                        warn!("🚨 Rule triggered: {} - {}", rule_name, alert.description);
                        // Update local counters (hot path) and enqueue the alert for processing
                        let is_crit = alert.severity == AlertSeverity::Critical;
                        self.local_stats.incr_alert(is_crit);
                        alerts_to_process.push(alert);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        error!("Rule evaluation error ({}): {}", rule_name, e);
                    }
                }
            }
            let proc_dur = proc_start.elapsed().as_secs_f64();
            metrics::histogram!("siem_processing_latency_seconds", proc_dur);
        }
        
        // Handle alerts: enqueue to Kafka for async processing by workers.
        for alert in alerts_to_process {
            // Try to send to Kafka with retries and DLQ. If all attempts fail, fallback to immediate processing.
            let send_res = self.kafka.send_alert_with_retry(&alert, 3, 200, Some(crate::queue::kafka::ALERTS_DLQ_TOPIC)).await;
            match send_res {
                Ok(_) => {
                    // record a successful enqueue
                    metrics::counter!("siem_alerts_sent_total", 1);
                    // also broadcast lightweight notification for real-time UIs
                    let _ = self.alert_tx.send(alert.clone());
                    // Notify the stats worker (non-blocking) to broadcast a coalesced update.
                    let _ = self.stats_notify_tx.try_send(());
                }
                Err(e) => {
                    // record fallback to DB
                    metrics::counter!("siem_alerts_fallback_db_total", 1);
                    error!("Failed to enqueue alert to Kafka after retries: {}. Falling back to immediate processing.", e);
                    // Fallback: persist, notify and trigger response engine via central alert manager
                    if let Err(e) = crate::alerting::manager::handle_alert(
                        self.db.clone(),
                        self.response_engine.clone(),
                        &alert,
                    ).await {
                        error!("Failed to handle alert: {}", e);
                    }
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
