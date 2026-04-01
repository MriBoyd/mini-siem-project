use std::collections::{HashMap, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use tokio::sync::{mpsc, broadcast};
use tracing::{info, error};

use crate::db::PostgresDb;
use crate::types::Alert;

const ALERT_DEDUP_WINDOW_SECONDS: i64 = 60;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AlertDedupKey {
    tenant_id: String,
    rule_id: String,
    entity: String,
    normalized_fingerprint: u64,
    window_bucket: i64,
}

fn normalize_fingerprint(input: &str) -> String {
    let mut normalized = String::with_capacity(input.len());
    let mut previous_was_space = false;
    let mut in_digit_run = false;

    for ch in input.chars() {
        if ch.is_ascii_digit() {
            if !in_digit_run {
                normalized.push('#');
                in_digit_run = true;
            }
            previous_was_space = false;
            continue;
        }

        in_digit_run = false;
        let mapped = ch.to_ascii_lowercase();
        if mapped.is_whitespace() {
            if !previous_was_space {
                normalized.push(' ');
                previous_was_space = true;
            }
        } else {
            previous_was_space = false;
            normalized.push(mapped);
        }
    }

    normalized.trim().to_string()
}

fn fingerprint_hash(alert: &Alert) -> u64 {
    let mut hasher = DefaultHasher::new();
    normalize_fingerprint(&alert.description).hash(&mut hasher);
    hasher.finish()
}

fn dedup_window_bucket(alert: &Alert) -> i64 {
    alert.last_seen.timestamp().div_euclid(ALERT_DEDUP_WINDOW_SECONDS.max(1))
}

fn alert_dedup_key(alert: &Alert) -> AlertDedupKey {
    AlertDedupKey {
        tenant_id: alert.tenant_id.clone(),
        rule_id: alert.rule_id.clone(),
        entity: alert.source_ip.clone(),
        normalized_fingerprint: fingerprint_hash(alert),
        window_bucket: dedup_window_bucket(alert),
    }
}

fn merge_alert(existing: &mut Alert, incoming: Alert) {
    let incoming_last_seen = incoming.last_seen;
    existing.first_seen = existing.first_seen.min(incoming.first_seen);
    existing.last_seen = existing.last_seen.max(incoming_last_seen);
    existing.events_count += incoming.events_count;
    existing.events.extend(incoming.events);

    if incoming_last_seen >= existing.last_seen {
        existing.description = incoming.description;
    }
}

/// Spawn a DB batcher that collects alerts and performs batched writes.
/// - Flushes when `batch_size` reached or `flush_interval_ms` elapsed.
pub fn spawn_db_batcher(
    db: Arc<PostgresDb>,
    mut rx: mpsc::Receiver<Alert>,
    mut shutdown_rx: broadcast::Receiver<()>,
    batch_size: usize,
    flush_interval_ms: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        info!("🗄️  DB batcher started (batch_size={}, flush_ms={})", batch_size, flush_interval_ms);

        let mut buffer: Vec<Alert> = Vec::with_capacity(batch_size);
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(flush_interval_ms));

        loop {
            tokio::select! {
                Some(alert) = rx.recv() => {
                    buffer.push(alert);
                    if buffer.len() >= batch_size {
                        if let Err(e) = flush_batch(&db, &mut buffer).await {
                            error!("Failed to flush alert batch: {}", e);
                        }
                    }
                }
                _ = interval.tick() => {
                    if !buffer.is_empty() {
                        if let Err(e) = flush_batch(&db, &mut buffer).await {
                            error!("Failed to flush alert batch: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("🛑 DB batcher received shutdown, flushing {} alerts", buffer.len());
                    if !buffer.is_empty() {
                        if let Err(e) = flush_batch(&db, &mut buffer).await {
                            error!("Failed to flush alert batch at shutdown: {}", e);
                        }
                    }
                    break;
                }
            }
        }

        info!("🗄️  DB batcher stopped");
    })
}

async fn flush_batch(db: &PostgresDb, buffer: &mut Vec<Alert>) -> anyhow::Result<()> {
    if buffer.is_empty() { return Ok(()); }

    let mut by_tenant: HashMap<String, HashMap<AlertDedupKey, Alert>> = HashMap::new();
    for alert in buffer.drain(..) {
        let tenant_id = alert.tenant_id.clone();
        let dedup_key = alert_dedup_key(&alert);
        by_tenant
            .entry(tenant_id)
            .or_default()
            .entry(dedup_key)
            .and_modify(|existing| merge_alert(existing, alert.clone()))
            .or_insert(alert);
    }

    for (tenant_id, tenant_alerts) in by_tenant.into_iter() {
        let ips: Vec<String> = tenant_alerts.values().map(|a| a.source_ip.clone()).collect();
        let unique_ips: Vec<String> = {
            let mut s = ips.clone();
            s.sort(); s.dedup();
            s
        };

        let existing = db.get_open_alerts_by_ips(&tenant_id, &unique_ips).await.unwrap_or_default();

        let mut existing_map: HashMap<AlertDedupKey, Alert> = HashMap::new();
        for e in existing.into_iter() {
            existing_map.entry(alert_dedup_key(&e)).or_insert(e);
        }

        let mut to_update: Vec<Alert> = Vec::new();
        let mut to_create: Vec<Alert> = Vec::new();

        for (dedup_key, alert) in tenant_alerts {
            if let Some(mut existing_alert) = existing_map.remove(&dedup_key) {
                merge_alert(&mut existing_alert, alert);
                to_update.push(existing_alert);
            } else {
                to_create.push(alert);
            }
        }

        if !to_create.is_empty() {
            db.create_alerts_batch(&to_create).await?;
        }

        if !to_update.is_empty() {
            if let Err(e) = db.upsert_alerts_batch(&to_update).await {
                error!("Failed to upsert alert batch: {}", e);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AlertSeverity, Log, LogSeverity};
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    fn test_log() -> Log {
        let now = Utc.timestamp_opt(1_700_000_000, 0).single().unwrap();
        Log {
            id: Uuid::new_v4(),
            tenant_id: "tenant-a".to_string(),
            timestamp: now,
            event_type: "login_failed".to_string(),
            source_ip: "10.0.0.1".to_string(),
            target_user: Some("alice".to_string()),
            service: Some("ssh".to_string()),
            message: "Failed password for alice from 10.0.0.1".to_string(),
            severity: LogSeverity::High,
            metadata: serde_json::Value::Null,
            received_at: now,
        }
    }

    fn test_alert(description: &str, rule_id: &str, source_ip: &str, last_seen_ts: i64) -> Alert {
        let last_seen = Utc.timestamp_opt(last_seen_ts, 0).single().unwrap();
        let mut alert = Alert::new(
            "tenant-a",
            rule_id,
            "rule-name",
            AlertSeverity::High,
            description,
            source_ip,
            vec![test_log()],
        );
        alert.first_seen = last_seen;
        alert.last_seen = last_seen;
        alert
    }

    #[test]
    fn dedup_key_changes_for_required_dimensions() {
        let base = test_alert(
            "Possible brute force attack from 10.0.0.1: 5 failed attempts",
            "rule-a",
            "10.0.0.1",
            1_700_000_000,
        );
        let same_semantics = test_alert(
            "possible brute force attack from 10.0.0.1: 9 failed attempts",
            "rule-a",
            "10.0.0.1",
            1_700_000_030,
        );
        let different_rule = test_alert(
            "possible brute force attack from 10.0.0.1: 9 failed attempts",
            "rule-b",
            "10.0.0.1",
            1_700_000_030,
        );
        let different_entity = test_alert(
            "possible brute force attack from 10.0.0.1: 9 failed attempts",
            "rule-a",
            "10.0.0.2",
            1_700_000_030,
        );
        let different_bucket = test_alert(
            "possible brute force attack from 10.0.0.1: 9 failed attempts",
            "rule-a",
            "10.0.0.1",
            1_700_000_090,
        );

        assert_eq!(alert_dedup_key(&base), alert_dedup_key(&same_semantics));
        assert_ne!(alert_dedup_key(&base), alert_dedup_key(&different_rule));
        assert_ne!(alert_dedup_key(&base), alert_dedup_key(&different_entity));
        assert_ne!(alert_dedup_key(&base), alert_dedup_key(&different_bucket));
    }
}
