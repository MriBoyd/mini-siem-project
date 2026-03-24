use actix_web::{get, web, HttpResponse, Responder, HttpRequest, HttpMessage};

use crate::api::server::AppState;
use crate::auth::jwt::Claims;
use crate::db::cache::Cache;

#[get("/dashboard/stats")]
pub async fn get_stats(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    // RBAC: only users with 'analyst' or 'admin' roles may view dashboard stats
    let exts = req.extensions();
    let claims = match exts.get::<Claims>() {
        Some(c) => c,
        None => return actix_web::error::ErrorUnauthorized("missing auth").error_response(),
    };

    let roles = &claims.roles;
    if !(roles.contains(&"analyst".to_string()) || roles.contains(&"admin".to_string())) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error":"insufficient role"}));
    }

    // Prefer fast in-memory (L1) backed Redis counters for dashboard responsiveness.
    // Fall back to the persisted Postgres singleton (`system_stats`) if Redis doesn't have values yet.
    let maybe_total_logs: Option<i64> = state.redis.get_counter("siem:stats:total_logs").await.ok().flatten().map(|v| v as i64);
    let maybe_total_alerts: Option<i64> = state.redis.get_counter("siem:stats:total_alerts").await.ok().flatten().map(|v| v as i64);
    let maybe_active_alerts: Option<i64> = state.redis.get_counter("siem:stats:active_alerts").await.ok().flatten().map(|v| v as i64);
    let maybe_critical_alerts: Option<i64> = state.redis.get_counter("siem:stats:critical_alerts").await.ok().flatten().map(|v| v as i64);

    if let (Some(total_logs), Some(total_alerts), Some(active_alerts), Some(critical_alerts)) = (
        maybe_total_logs,
        maybe_total_alerts,
        maybe_active_alerts,
        maybe_critical_alerts,
    ) {
        return HttpResponse::Ok().json(serde_json::json!({
            "total_logs": total_logs,
            "total_alerts": total_alerts,
            "active_alerts": active_alerts,
            "critical_alerts": critical_alerts,
        }));
    }

    // Fallback: read persisted snapshot from Postgres and seed Redis for faster subsequent reads.
    match state.db.get_stats().await {
        Ok((total_logs, total_alerts, active_alerts, critical_alerts)) => {
            // Best-effort: seed Redis counters so L1/cache path picks them up quickly.
            let _ = state.redis.set_counter("siem:stats:total_logs", total_logs as u64, Some(86400)).await;
            let _ = state.redis.set_counter("siem:stats:total_alerts", total_alerts as u64, Some(86400)).await;
            let _ = state.redis.set_counter("siem:stats:active_alerts", active_alerts as u64, Some(86400)).await;
            let _ = state.redis.set_counter("siem:stats:critical_alerts", critical_alerts as u64, Some(86400)).await;

            HttpResponse::Ok().json(serde_json::json!({
                "total_logs": total_logs,
                "total_alerts": total_alerts,
                "active_alerts": active_alerts,
                "critical_alerts": critical_alerts,
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("failed to load stats: {}", e),
        })),
    }
}
