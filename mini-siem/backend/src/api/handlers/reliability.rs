use actix_web::{get, post, web, HttpMessage, HttpRequest, HttpResponse, Responder};
use chrono::Utc;
use uuid::Uuid;

use crate::api::server::AppState;
use crate::api::tenant::enforce_tenant_fixed_window;
use crate::auth::jwt::Claims;
use crate::db::models::reliability::ReliabilityReportCreate;
use crate::reliability::{build_reliability_overview, create_reliability_report, health_probe_summary, replay_recent_logs};

fn has_reliability_access(claims: &Claims) -> bool {
    claims.roles.contains(&"analyst".to_string()) || claims.roles.contains(&"admin".to_string())
}

#[get("/reliability/overview")]
pub async fn get_reliability_overview(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !has_reliability_access(&claims) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "insufficient role"}));
    }

    if let Err(response) = enforce_tenant_fixed_window(&state, &claims.tenant_id, "api_requests", state.tenant_limits.api_requests_per_minute, 1).await {
        return response;
    }

    match build_reliability_overview(&state, &claims.tenant_id).await {
        Ok(overview) => HttpResponse::Ok().json(overview),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to build reliability overview: {}", e)})),
    }
}

#[get("/reliability/reports")]
pub async fn list_reliability_reports(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !has_reliability_access(&claims) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "insufficient role"}));
    }

    match state.db.list_reliability_reports(&claims.tenant_id, 24).await {
        Ok(reports) => HttpResponse::Ok().json(reports),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to list reliability reports: {}", e)})),
    }
}

#[post("/reliability/reports")]
pub async fn create_report(req: HttpRequest, state: web::Data<AppState>, body: web::Json<ReliabilityReportCreate>) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !has_reliability_access(&claims) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "insufficient role"}));
    }

    let mut report = body.into_inner();
    report.tenant_id = claims.tenant_id.clone();

    match create_reliability_report(&state, report).await {
        Ok(record) => HttpResponse::Ok().json(record),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to save reliability report: {}", e)})),
    }
}

#[post("/reliability/drills/replay")]
pub async fn run_replay_drill(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !has_reliability_access(&claims) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "insufficient role"}));
    }

    let started_at = Utc::now();
    let summary = match replay_recent_logs(&state, &claims.tenant_id, 25).await {
        Ok(summary) => summary,
        Err(e) => serde_json::json!({"error": format!("replay drill failed: {}", e)}),
    };
    let completed_at = Utc::now();
    let status = if summary.get("error").is_some() { "failed" } else { "passed" };
    let report = ReliabilityReportCreate {
        tenant_id: claims.tenant_id.clone(),
        report_type: "replay_drill".to_string(),
        drill_name: format!("replay-drill-{}", Uuid::new_v4()),
        status: status.to_string(),
        started_at,
        completed_at,
        summary_json: summary,
    };

    match create_reliability_report(&state, report).await {
        Ok(record) => HttpResponse::Ok().json(record),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to save replay drill report: {}", e)})),
    }
}

#[post("/reliability/drills/chaos")]
pub async fn run_chaos_drill(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !has_reliability_access(&claims) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "insufficient role"}));
    }

    let started_at = Utc::now();
    let summary = health_probe_summary(&state).await;
    let completed_at = Utc::now();
    let status = if summary.get("all_healthy").and_then(|value| value.as_bool()).unwrap_or(false) { "passed" } else { "failed" };
    let report = ReliabilityReportCreate {
        tenant_id: claims.tenant_id.clone(),
        report_type: "chaos_drill".to_string(),
        drill_name: format!("chaos-drill-{}", Uuid::new_v4()),
        status: status.to_string(),
        started_at,
        completed_at,
        summary_json: summary,
    };

    match create_reliability_report(&state, report).await {
        Ok(record) => HttpResponse::Ok().json(record),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to save chaos drill report: {}", e)})),
    }
}
