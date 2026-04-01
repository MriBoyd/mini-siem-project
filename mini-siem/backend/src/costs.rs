use anyhow::Result;
use chrono::{Datelike, Utc};

use crate::api::handlers::logs::IngestLogRequest;
use crate::api::server::AppState;
use crate::db::cache::Cache;
use crate::db::models::data_cost::{CostDecision, TenantCostDashboard, TenantCostDimensionUsage, TenantDataCostPolicy};
use crate::types::LogSeverity;

const COST_POLICY_CACHE_PREFIX: &str = "siem:tenant:";
const COST_USAGE_PREFIX: &str = "siem:tenant:";

fn today_bucket() -> String {
    let now = Utc::now();
    format!("{:04}-{:02}-{:02}", now.year(), now.month(), now.day())
}

pub fn policy_cache_key(tenant_id: &str) -> String {
    format!("{}{}:cost:policy", COST_POLICY_CACHE_PREFIX, tenant_id)
}

pub fn usage_bytes_key(tenant_id: &str) -> String {
    format!("{}{}:cost:{}:bytes", COST_USAGE_PREFIX, tenant_id, today_bucket())
}

pub fn usage_logs_key(tenant_id: &str) -> String {
    format!("{}{}:cost:{}:logs", COST_USAGE_PREFIX, tenant_id, today_bucket())
}

pub fn usage_sampled_key(tenant_id: &str) -> String {
    format!("{}{}:cost:{}:sampled", COST_USAGE_PREFIX, tenant_id, today_bucket())
}

pub fn usage_dropped_key(tenant_id: &str) -> String {
    format!("{}{}:cost:{}:dropped", COST_USAGE_PREFIX, tenant_id, today_bucket())
}

fn rank_key(tenant_id: &str, dimension: &str) -> String {
    format!("{}{}:cost:{}:{}:rank", COST_USAGE_PREFIX, tenant_id, today_bucket(), dimension)
}

pub fn classify_source(log: &IngestLogRequest) -> String {
    if log.source_ip.is_empty() {
        "unknown".to_string()
    } else {
        log.source_ip.clone()
    }
}

pub fn classify_integration(log: &IngestLogRequest) -> String {
    log.service.clone().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| log.event_type.clone())
}

pub fn classify_team(log: &IngestLogRequest) -> String {
    if let Some(metadata) = log.metadata.as_ref() {
        if let Some(value) = metadata.get("team").and_then(|value| value.as_str()) {
            return value.to_string();
        }
        if let Some(value) = metadata.get("team_id").and_then(|value| value.as_str()) {
            return value.to_string();
        }
        if let Some(value) = metadata.get("owner_team").and_then(|value| value.as_str()) {
            return value.to_string();
        }
    }

    "unassigned".to_string()
}

pub fn estimated_cost_bytes(log: &IngestLogRequest) -> u64 {
    let mut total = log.event_type.len() + log.source_ip.len() + log.message.len();
    total += log.target_user.as_ref().map(|value| value.len()).unwrap_or(0);
    total += log.service.as_ref().map(|value| value.len()).unwrap_or(0);
    if let Some(metadata) = log.metadata.as_ref() {
        total += metadata.to_string().len();
    }
    total as u64
}

pub fn is_low_value_event(log: &IngestLogRequest) -> bool {
    let event_type = log.event_type.to_lowercase();
    let message = log.message.to_lowercase();

    matches!(log.severity.unwrap_or(LogSeverity::Info), LogSeverity::Debug | LogSeverity::Info)
        || event_type.contains("heartbeat")
        || event_type.contains("metrics")
        || event_type.contains("debug")
        || event_type.contains("health")
        || message.contains("health check")
        || message.contains("keepalive")
}

fn schema_drop_reason(log: &IngestLogRequest, policy: &TenantDataCostPolicy) -> Option<String> {
    let rules = policy.schema_drop_rules.as_array()?;
    for rule in rules {
        let field = rule.get("field").and_then(|value| value.as_str()).unwrap_or("");
        let op = rule.get("op").and_then(|value| value.as_str()).unwrap_or("");
        let value = rule.get("value");

        let matches = match field {
            "event_type" => match op {
                "==" => value.and_then(|v| v.as_str()).map(|expected| log.event_type == expected).unwrap_or(false),
                "in" => value.and_then(|v| v.as_array()).map(|items| items.iter().filter_map(|v| v.as_str()).any(|candidate| candidate == log.event_type)).unwrap_or(false),
                _ => false,
            },
            "severity" => {
                let severity = log.severity.unwrap_or(LogSeverity::Info).to_string();
                match op {
                    "==" => value.and_then(|v| v.as_str()).map(|expected| severity == expected).unwrap_or(false),
                    "in" => value.and_then(|v| v.as_array()).map(|items| items.iter().filter_map(|v| v.as_str()).any(|candidate| candidate == severity)).unwrap_or(false),
                    _ => false,
                }
            }
            "message" => match op {
                "contains" => value.and_then(|v| v.as_str()).map(|needle| log.message.to_lowercase().contains(&needle.to_lowercase())).unwrap_or(false),
                _ => false,
            },
            "service" => match op {
                "==" => value.and_then(|v| v.as_str()).map(|expected| log.service.as_deref() == Some(expected)).unwrap_or(false),
                _ => false,
            },
            _ => false,
        };

        if matches {
            return Some(format!("schema rule matched {} {}", field, op));
        }
    }

    None
}

fn current_pressure(current_bytes: u64, budget_bytes: i64) -> f64 {
    if budget_bytes <= 0 {
        0.0
    } else {
        current_bytes as f64 / budget_bytes as f64
    }
}

fn dimension_bytes_key(tenant_id: &str, dimension: &str, key: &str) -> String {
    format!("{}{}:cost:{}:{}:{}:bytes", COST_USAGE_PREFIX, tenant_id, today_bucket(), dimension, key)
}

fn dimension_logs_key(tenant_id: &str, dimension: &str, key: &str) -> String {
    format!("{}{}:cost:{}:{}:{}:logs", COST_USAGE_PREFIX, tenant_id, today_bucket(), dimension, key)
}

fn dimension_sampled_key(tenant_id: &str, dimension: &str, key: &str) -> String {
    format!("{}{}:cost:{}:{}:{}:sampled", COST_USAGE_PREFIX, tenant_id, today_bucket(), dimension, key)
}

fn dimension_dropped_key(tenant_id: &str, dimension: &str, key: &str) -> String {
    format!("{}{}:cost:{}:{}:{}:dropped", COST_USAGE_PREFIX, tenant_id, today_bucket(), dimension, key)
}

async fn enrich_dimension_rows(state: &AppState, tenant_id: &str, dimension: &str, rows: &mut Vec<TenantCostDimensionUsage>) {
    for row in rows.iter_mut() {
        row.logs = state.redis.get_counter(&dimension_logs_key(tenant_id, dimension, &row.key)).await.ok().flatten().unwrap_or(0) as u64;
        row.sampled = state.redis.get_counter(&dimension_sampled_key(tenant_id, dimension, &row.key)).await.ok().flatten().unwrap_or(0) as u64;
        row.dropped = state.redis.get_counter(&dimension_dropped_key(tenant_id, dimension, &row.key)).await.ok().flatten().unwrap_or(0) as u64;
    }
}

pub async fn load_tenant_cost_policy(state: &AppState, tenant_id: &str) -> Result<TenantDataCostPolicy> {
    let key = policy_cache_key(tenant_id);
    if let Some(raw) = state.redis.get_string(&key).await? {
        if let Ok(policy) = serde_json::from_str::<TenantDataCostPolicy>(&raw) {
            return Ok(policy);
        }
    }

    let policy = state.db.get_tenant_data_cost_policy(tenant_id).await?;
    let _ = state.redis.set_string(&key, &serde_json::to_string(&policy)?, Some(900)).await;
    Ok(policy)
}

pub async fn save_tenant_cost_policy(state: &AppState, policy: &TenantDataCostPolicy) -> Result<TenantDataCostPolicy> {
    let record = state.db.upsert_tenant_data_cost_policy(policy).await?;
    let key = policy_cache_key(&record.tenant_id);
    let _ = state.redis.set_string(&key, &serde_json::to_string(&record)?, Some(900)).await;
    Ok(record)
}

pub async fn evaluate_cost_decision(state: &AppState, tenant_id: &str, log: &IngestLogRequest) -> Result<(TenantDataCostPolicy, CostDecision)> {
    let policy = load_tenant_cost_policy(state, tenant_id).await?;
    let source_key = classify_source(log);
    let integration_key = classify_integration(log);
    let team_key = classify_team(log);
    let estimated_bytes = estimated_cost_bytes(log);

    let usage_key = usage_bytes_key(tenant_id);
    let current_bytes = state.redis.get_counter(&usage_key).await?.unwrap_or(0) as u64;
    let tenant_pressure = current_pressure(current_bytes, policy.daily_ingest_bytes_budget);

    let source_budget = policy.source_budgets.get(&source_key).and_then(|value| value.as_i64()).unwrap_or(policy.daily_ingest_bytes_budget);
    let integration_budget = policy.integration_budgets.get(&integration_key).and_then(|value| value.as_i64()).unwrap_or(policy.daily_ingest_bytes_budget);
    let team_budget = policy.team_budgets.get(&team_key).and_then(|value| value.as_i64()).unwrap_or(policy.daily_ingest_bytes_budget);

    let source_pressure = current_pressure(state.redis.get_counter(&dimension_bytes_key(tenant_id, "source", &source_key)).await?.unwrap_or(0) as u64, source_budget);
    let integration_pressure = current_pressure(state.redis.get_counter(&dimension_bytes_key(tenant_id, "integration", &integration_key)).await?.unwrap_or(0) as u64, integration_budget);
    let team_pressure = current_pressure(state.redis.get_counter(&dimension_bytes_key(tenant_id, "team", &team_key)).await?.unwrap_or(0) as u64, team_budget);

    let pressure = tenant_pressure.max(source_pressure).max(integration_pressure).max(team_pressure);
    let schema_drop = schema_drop_reason(log, &policy);
    let low_value = is_low_value_event(log);
    let severe = matches!(log.severity.unwrap_or(LogSeverity::Info), LogSeverity::High | LogSeverity::Critical);

    let mut action = "keep".to_string();
    let mut keep = true;
    let mut sampled = false;
    let mut dropped = false;
    let mut sample_rate_percent = policy.high_value_sampling_percent.clamp(1, 100);
    let mut reason = "kept".to_string();

    if let Some(schema_reason) = schema_drop {
        if policy.drop_low_value_when_over_budget || low_value {
            action = "dropped".to_string();
            keep = false;
            dropped = true;
            reason = schema_reason;
            sample_rate_percent = 0;
        }
    }

    if keep {
        if severe {
            sample_rate_percent = policy.high_value_sampling_percent.clamp(1, 100);
        } else if low_value || pressure >= 1.0 {
            sample_rate_percent = policy.low_value_sampling_percent.clamp(1, 100);
        }

        if policy.sampling_enabled {
            let hash_seed = format!("{}:{}:{}:{}", tenant_id, log.source_ip, log.event_type, log.message);
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            hash_seed.hash(&mut hasher);
            let bucket = (hasher.finish() % 100) as i32 + 1;

            if bucket > sample_rate_percent {
                if low_value || pressure >= 1.0 {
                    action = "sampled".to_string();
                    keep = false;
                    sampled = true;
                    reason = format!("sampled at {}% due to pressure {:.2}", sample_rate_percent, pressure);
                }
            }
        }
    }

    if !keep && !sampled && !dropped {
        reason = "dropped by cost controller".to_string();
    }

    Ok((
        policy,
        CostDecision {
            action,
            keep,
            sampled,
            dropped,
            sample_rate_percent,
            reason,
            estimated_bytes,
            source_key,
            integration_key,
            team_key,
        },
    ))
}

pub async fn record_cost_usage(state: &AppState, tenant_id: &str, decision: &CostDecision) -> Result<()> {
    let usage_key = usage_bytes_key(tenant_id);
    let logs_key = usage_logs_key(tenant_id);
    let sampled_key = usage_sampled_key(tenant_id);
    let dropped_key = usage_dropped_key(tenant_id);

    let _ = state.redis.incr_by(&usage_key, decision.estimated_bytes, 86_400).await;
    let _ = state.redis.increment_counter(&logs_key, 86_400).await;

    let source_bytes_key = dimension_bytes_key(tenant_id, "source", &decision.source_key);
    let source_logs_key = dimension_logs_key(tenant_id, "source", &decision.source_key);
    let integration_bytes_key = dimension_bytes_key(tenant_id, "integration", &decision.integration_key);
    let integration_logs_key = dimension_logs_key(tenant_id, "integration", &decision.integration_key);
    let team_bytes_key = dimension_bytes_key(tenant_id, "team", &decision.team_key);
    let team_logs_key = dimension_logs_key(tenant_id, "team", &decision.team_key);

    let _ = state.redis.incr_by(&source_bytes_key, decision.estimated_bytes, 86_400).await;
    let _ = state.redis.increment_counter(&source_logs_key, 86_400).await;
    let _ = state.redis.incr_by(&integration_bytes_key, decision.estimated_bytes, 86_400).await;
    let _ = state.redis.increment_counter(&integration_logs_key, 86_400).await;
    let _ = state.redis.incr_by(&team_bytes_key, decision.estimated_bytes, 86_400).await;
    let _ = state.redis.increment_counter(&team_logs_key, 86_400).await;

    let source_rank = rank_key(tenant_id, "source");
    let integration_rank = rank_key(tenant_id, "integration");
    let team_rank = rank_key(tenant_id, "team");

    let _ = state.redis.zincrby(&source_rank, &decision.source_key, decision.estimated_bytes as f64).await;
    let _ = state.redis.zincrby(&integration_rank, &decision.integration_key, decision.estimated_bytes as f64).await;
    let _ = state.redis.zincrby(&team_rank, &decision.team_key, decision.estimated_bytes as f64).await;

    if decision.sampled {
        let _ = state.redis.increment_counter(&sampled_key, 86_400).await;
        let _ = state.redis.increment_counter(&dimension_sampled_key(tenant_id, "source", &decision.source_key), 86_400).await;
        let _ = state.redis.increment_counter(&dimension_sampled_key(tenant_id, "integration", &decision.integration_key), 86_400).await;
        let _ = state.redis.increment_counter(&dimension_sampled_key(tenant_id, "team", &decision.team_key), 86_400).await;
    }
    if decision.dropped {
        let _ = state.redis.increment_counter(&dropped_key, 86_400).await;
        let _ = state.redis.increment_counter(&dimension_dropped_key(tenant_id, "source", &decision.source_key), 86_400).await;
        let _ = state.redis.increment_counter(&dimension_dropped_key(tenant_id, "integration", &decision.integration_key), 86_400).await;
        let _ = state.redis.increment_counter(&dimension_dropped_key(tenant_id, "team", &decision.team_key), 86_400).await;
    }

    Ok(())
}

pub async fn build_cost_dashboard(state: &AppState, tenant_id: &str) -> Result<TenantCostDashboard> {
    let policy = load_tenant_cost_policy(state, tenant_id).await?;
    let usage_bytes_today = state.redis.get_counter(&usage_bytes_key(tenant_id)).await?.unwrap_or(0) as u64;
    let usage_logs_today = state.redis.get_counter(&usage_logs_key(tenant_id)).await?.unwrap_or(0) as u64;
    let sampled_logs_today = state.redis.get_counter(&usage_sampled_key(tenant_id)).await?.unwrap_or(0) as u64;
    let dropped_logs_today = state.redis.get_counter(&usage_dropped_key(tenant_id)).await?.unwrap_or(0) as u64;

    let top_sources = state.redis.zrevrange_withscores(&rank_key(tenant_id, "source"), 0, 9).await.unwrap_or_default();
    let top_integrations = state.redis.zrevrange_withscores(&rank_key(tenant_id, "integration"), 0, 9).await.unwrap_or_default();
    let top_teams = state.redis.zrevrange_withscores(&rank_key(tenant_id, "team"), 0, 9).await.unwrap_or_default();

    let to_dimension_usage = |dimension: &str, values: Vec<(String, f64)>| -> Vec<TenantCostDimensionUsage> {
        values.into_iter().map(|(key, bytes)| TenantCostDimensionUsage {
            dimension: dimension.to_string(),
            key: key.clone(),
            bytes: bytes.max(0.0) as u64,
            logs: 0,
            sampled: 0,
            dropped: 0,
        }).collect()
    };

    let mut top_sources = to_dimension_usage("source", top_sources);
    let mut top_integrations = to_dimension_usage("integration", top_integrations);
    let mut top_teams = to_dimension_usage("team", top_teams);

    enrich_dimension_rows(state, tenant_id, "source", &mut top_sources).await;
    enrich_dimension_rows(state, tenant_id, "integration", &mut top_integrations).await;
    enrich_dimension_rows(state, tenant_id, "team", &mut top_teams).await;

    let tenant_budget_pressure = current_pressure(usage_bytes_today, policy.daily_ingest_bytes_budget);
    let hot_storage_pressure = current_pressure(usage_bytes_today, policy.hot_storage_bytes_budget);
    let warm_storage_pressure = current_pressure(usage_bytes_today, policy.warm_storage_bytes_budget);
    let cold_storage_pressure = current_pressure(usage_bytes_today, policy.cold_storage_bytes_budget);

    Ok(TenantCostDashboard {
        tenant_id: tenant_id.to_string(),
        policy,
        usage_bytes_today,
        usage_logs_today,
        sampled_logs_today,
        dropped_logs_today,
        tenant_budget_pressure,
        hot_storage_pressure,
        warm_storage_pressure,
        cold_storage_pressure,
        top_sources,
        top_integrations,
        top_teams,
    })
}