use actix_web::{get, HttpResponse, Responder};
use chrono::Utc;

use crate::types::{Alert, AlertSeverity, Log};

#[get("/api/v1/alerts")]
pub async fn list_alerts() -> impl Responder {
    // TODO: Replace with real query logic against database / alert store.
    // For now, return a small set of example alerts to drive UI development.

    let sample_event = Log::new(
        "login_failed".to_string(),
        "10.0.0.5".to_string(),
        "Failed password for root from 10.0.0.5".to_string(),
    );

    let sample_alert = Alert::new(
        "rule-1",
        "Failed Login Attempts",
        AlertSeverity::High,
        "Multiple failed SSH logins detected",
        "10.0.0.5",
        vec![sample_event],
    );

    let now = Utc::now();
    let alert2 = Alert {
        id: uuid::Uuid::new_v4(),
        rule_id: "rule-2".to_string(),
        rule_name: "Suspicious Process".to_string(),
        severity: AlertSeverity::Medium,
        description: "Execution of a rare process detected".to_string(),
        source_ip: "172.16.0.22".to_string(),
        events: vec![],
        first_seen: now,
        last_seen: now,
        status: crate::types::AlertStatus::Investigating,
        events_count: 0,
    };

    HttpResponse::Ok().json(vec![sample_alert, alert2])
}
