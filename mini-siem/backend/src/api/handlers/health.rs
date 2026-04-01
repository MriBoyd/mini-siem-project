use std::collections::BTreeMap;

use actix_web::{get, web, HttpResponse, Responder};
use chrono::Utc;

use crate::api::server::AppState;
use crate::db::cache::Cache;

#[derive(serde::Serialize)]
struct ServiceHealth {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_seen_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_seen_seconds_ago: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

#[derive(serde::Serialize)]
struct DetailedHealth {
    status: String,
    version: String,
    services: BTreeMap<String, ServiceHealth>,
}

async fn heartbeat_status(state: &AppState, key: &str, max_age_secs: i64) -> ServiceHealth {
    match state.redis.get_string(key).await {
        Ok(Some(value)) => match value.parse::<i64>() {
            Ok(timestamp) => {
                let age = Utc::now().timestamp().saturating_sub(timestamp);
                let status = if age <= max_age_secs { "healthy" } else { "degraded" };
                ServiceHealth {
                    status: status.to_string(),
                    last_seen_at: Some(value),
                    last_seen_seconds_ago: Some(age),
                    details: None,
                }
            }
            Err(_) => ServiceHealth {
                status: "degraded".to_string(),
                last_seen_at: Some(value),
                last_seen_seconds_ago: None,
                details: Some("invalid heartbeat timestamp".to_string()),
            },
        },
        Ok(None) => ServiceHealth {
            status: "down".to_string(),
            last_seen_at: None,
            last_seen_seconds_ago: None,
            details: Some("no heartbeat recorded yet".to_string()),
        },
        Err(e) => ServiceHealth {
            status: "down".to_string(),
            last_seen_at: None,
            last_seen_seconds_ago: None,
            details: Some(format!("heartbeat lookup failed: {}", e)),
        },
    }
}

#[get("/health/services")]
pub async fn detailed_health(state: web::Data<AppState>) -> impl Responder {
    let mut services = BTreeMap::new();

    services.insert(
        "api".to_string(),
        ServiceHealth {
            status: "healthy".to_string(),
            last_seen_at: Some(Utc::now().to_rfc3339()),
            last_seen_seconds_ago: Some(0),
            details: Some("api endpoint responding".to_string()),
        },
    );

    services.insert(
        "postgres".to_string(),
        match state.db.ping().await {
            Ok(_) => ServiceHealth { status: "healthy".to_string(), last_seen_at: None, last_seen_seconds_ago: None, details: Some("postgres reachable".to_string()) },
            Err(e) => ServiceHealth { status: "down".to_string(), last_seen_at: None, last_seen_seconds_ago: None, details: Some(format!("postgres ping failed: {}", e)) },
        },
    );

    services.insert(
        "redis".to_string(),
        match state.redis.ping().await {
            Ok(_) => ServiceHealth { status: "healthy".to_string(), last_seen_at: None, last_seen_seconds_ago: None, details: Some("redis reachable".to_string()) },
            Err(e) => ServiceHealth { status: "down".to_string(), last_seen_at: None, last_seen_seconds_ago: None, details: Some(format!("redis ping failed: {}", e)) },
        },
    );

    services.insert(
        "elasticsearch".to_string(),
        match state.elastic.borrow().clone() {
            Some(client) => match client.health().await {
                Ok(_) => ServiceHealth { status: "healthy".to_string(), last_seen_at: None, last_seen_seconds_ago: None, details: Some("elasticsearch reachable".to_string()) },
                Err(e) => ServiceHealth { status: "down".to_string(), last_seen_at: None, last_seen_seconds_ago: None, details: Some(format!("elasticsearch health failed: {}", e)) },
            },
            None => ServiceHealth { status: "down".to_string(), last_seen_at: None, last_seen_seconds_ago: None, details: Some("elasticsearch not configured".to_string()) },
        },
    );

    services.insert(
        "kafka".to_string(),
        match state.kafka.health().await {
            Ok(_) => ServiceHealth { status: "healthy".to_string(), last_seen_at: None, last_seen_seconds_ago: None, details: Some("kafka metadata reachable".to_string()) },
            Err(e) => ServiceHealth { status: "down".to_string(), last_seen_at: None, last_seen_seconds_ago: None, details: Some(format!("kafka health failed: {}", e)) },
        },
    );

    services.insert("agent".to_string(), heartbeat_status(&state, "siem:health:agent_last_seen", 300).await);
    services.insert("indexer".to_string(), heartbeat_status(&state, "siem:health:indexer_last_seen", 300).await);
    services.insert("alert_pipeline".to_string(), heartbeat_status(&state, "siem:health:alert_pipeline_last_seen", 300).await);

    let overall = if services.values().all(|service| service.status == "healthy") {
        "healthy"
    } else if services.values().any(|service| service.status == "healthy") {
        "degraded"
    } else {
        "down"
    };

    HttpResponse::Ok().json(DetailedHealth {
        status: overall.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        services,
    })
}

#[get("/health")]
pub async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// root endpoint, useful for browsers hitting `/`
#[get("/")]
pub async fn root() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Mini SIEM API is running",
        "health": "/health"
    }))
}