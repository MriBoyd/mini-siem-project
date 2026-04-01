use anyhow::Result;
use chrono::Utc;
use std::sync::Arc;
use tokio::time::Duration;

use crate::api::server::AppState;
use crate::db::cache::Cache;
use crate::db::models::reliability::{ReliabilityOverview, ReliabilityReportCreate, ReliabilitySloSnapshot};
use crate::types::Log;

const INGEST_AVAILABILITY_KEY: &str = "siem:reliability:ingest_availability_samples";
const DETECTION_LATENCY_KEY: &str = "siem:reliability:detection_latency_ms_samples";
const ALERT_DELIVERY_LATENCY_KEY: &str = "siem:reliability:alert_delivery_latency_ms_samples";
const DEFAULT_SAMPLE_WINDOW: usize = 512;
const DEFAULT_AVAILABILITY_WINDOW: usize = 10080;

fn percentile(values: &[f64], quantile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let mut sorted = values.to_vec();
    sorted.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    let index = ((sorted.len() as f64 - 1.0) * quantile.clamp(0.0, 1.0)).round() as usize;
    sorted[index.min(sorted.len().saturating_sub(1))]
}

async fn read_samples(redis: &dyn Cache, key: &str) -> Vec<f64> {
    match redis.lrange(key, 0, -1).await {
        Ok(values) => values.into_iter().filter_map(|value| value.parse::<f64>().ok()).collect(),
        Err(_) => Vec::new(),
    }
}

pub async fn record_latency_sample(redis: &dyn Cache, key: &str, latency_ms: f64) -> Result<()> {
    redis.lpush_trim(key, &format!("{latency_ms:.3}"), DEFAULT_SAMPLE_WINDOW, Some(7 * 24 * 60 * 60)).await
}

pub async fn record_detection_latency(redis: &dyn Cache, latency_ms: f64) -> Result<()> {
    record_latency_sample(redis, DETECTION_LATENCY_KEY, latency_ms).await
}

pub async fn record_alert_delivery_latency(redis: &dyn Cache, latency_ms: f64) -> Result<()> {
    record_latency_sample(redis, ALERT_DELIVERY_LATENCY_KEY, latency_ms).await
}

pub async fn record_ingest_availability_sample(state: &AppState) -> Result<()> {
    let elastic_client = state.elastic.borrow().clone();
    let elastic_ok = match elastic_client {
        Some(client) => client.health().await.is_ok(),
        None => false,
    };

    let available = state.db.ping().await.is_ok()
        && state.redis.ping().await.is_ok()
        && state.kafka.health().await.is_ok()
        && elastic_ok;

    state.redis.lpush_trim(INGEST_AVAILABILITY_KEY, if available { "1" } else { "0" }, DEFAULT_AVAILABILITY_WINDOW, Some(8 * 24 * 60 * 60)).await?;
    Ok(())
}

pub async fn build_reliability_overview(state: &AppState, tenant_id: &str) -> Result<ReliabilityOverview> {
    let ingest_samples = read_samples(&state.redis, INGEST_AVAILABILITY_KEY).await;
    let detection_samples = read_samples(&state.redis, DETECTION_LATENCY_KEY).await;
    let alert_delivery_samples = read_samples(&state.redis, ALERT_DELIVERY_LATENCY_KEY).await;

    let ingest_availability_observed_percent = if ingest_samples.is_empty() {
        0.0
    } else {
        ingest_samples.iter().filter(|value| **value >= 0.5).count() as f64 / ingest_samples.len() as f64 * 100.0
    };

    let detection_latency_p95_ms = percentile(&detection_samples, 0.95);
    let detection_latency_p99_ms = percentile(&detection_samples, 0.99);
    let alert_delivery_latency_p95_ms = percentile(&alert_delivery_samples, 0.95);
    let alert_delivery_latency_p99_ms = percentile(&alert_delivery_samples, 0.99);

    let mut status = "healthy".to_string();
    if ingest_availability_observed_percent < 99.0 || detection_latency_p95_ms > 2000.0 || alert_delivery_latency_p95_ms > 2000.0 {
        status = "degraded".to_string();
    }
    if ingest_availability_observed_percent < 95.0 {
        status = "down".to_string();
    }

    let snapshot = ReliabilitySloSnapshot {
        ingest_availability_target_percent: 99.9,
        ingest_availability_observed_percent,
        detection_latency_target_p95_ms: 2000.0,
        detection_latency_p95_ms,
        detection_latency_p99_ms,
        alert_delivery_latency_target_p95_ms: 2000.0,
        alert_delivery_latency_p95_ms,
        alert_delivery_latency_p99_ms,
        sample_count: ingest_samples.len().max(detection_samples.len()).max(alert_delivery_samples.len()) as u64,
        status,
    };

    let recent_reports = state.db.list_reliability_reports(tenant_id, 12).await?;

    Ok(ReliabilityOverview {
        tenant_id: tenant_id.to_string(),
        snapshot,
        recent_reports,
    })
}

pub async fn create_reliability_report(state: &AppState, report: ReliabilityReportCreate) -> Result<crate::db::models::reliability::ReliabilityReportRecord> {
    state.db.insert_reliability_report(&report).await
}

pub async fn replay_recent_logs(state: &AppState, tenant_id: &str, limit: usize) -> Result<serde_json::Value> {
    let Some(elastic) = state.elastic.borrow().clone() else {
        return Ok(serde_json::json!({"replayed": 0, "reason": "elasticsearch unavailable"}));
    };

    let query = serde_json::json!({ "term": { "tenant_id": tenant_id } });
    let response = elastic.search(&state.elastic_index, query, 0, limit.max(1)).await?;

    let mut replayed = 0usize;
    let started = Utc::now();

    if let Some(hits) = response.pointer("/hits/hits").and_then(|value| value.as_array()) {
        for hit in hits {
            let Some(source) = hit.get("_source") else { continue };
            let Ok(mut log) = serde_json::from_value::<Log>(source.clone()) else { continue };
            log.metadata = serde_json::json!({
                "drill": "replay",
                "original_id": log.id,
                "replayed_at": started.to_rfc3339(),
            });
            log.received_at = Utc::now();
            let _ = state.ingest_tx.send(Arc::new(log)).await;
            replayed += 1;
        }
    }

    Ok(serde_json::json!({
        "replayed": replayed,
        "limit": limit,
        "started_at": started,
        "completed_at": Utc::now(),
    }))
}

pub async fn health_probe_summary(state: &AppState) -> serde_json::Value {
    let db_ok = state.db.ping().await.is_ok();
    let redis_ok = state.redis.ping().await.is_ok();
    let kafka_ok = state.kafka.health().await.is_ok();
    let elastic_client = state.elastic.borrow().clone();
    let elastic_ok = match elastic_client {
        Some(client) => client.health().await.is_ok(),
        None => false,
    };

    serde_json::json!({
        "db": db_ok,
        "redis": redis_ok,
        "kafka": kafka_ok,
        "elasticsearch": elastic_ok,
        "all_healthy": db_ok && redis_ok && kafka_ok && elastic_ok,
    })
}

pub fn default_report_window() -> Duration {
    Duration::from_secs(7 * 24 * 60 * 60)
}
