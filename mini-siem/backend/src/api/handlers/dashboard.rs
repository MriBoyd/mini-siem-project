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

    let tenant_prefix = format!("siem:tenant:{}:stats", claims.tenant_id);
    let maybe_total_logs: Option<i64> = state.redis.get_counter(&format!("{}:total_logs", tenant_prefix)).await.ok().flatten().map(|v| v as i64);
    let maybe_total_alerts: Option<i64> = state.redis.get_counter(&format!("{}:total_alerts", tenant_prefix)).await.ok().flatten().map(|v| v as i64);
    let maybe_active_alerts: Option<i64> = state.redis.get_counter(&format!("{}:active_alerts", tenant_prefix)).await.ok().flatten().map(|v| v as i64);
    let maybe_critical_alerts: Option<i64> = state.redis.get_counter(&format!("{}:critical_alerts", tenant_prefix)).await.ok().flatten().map(|v| v as i64);

    if let (Some(total_logs), Some(total_alerts), Some(active_alerts), Some(critical_alerts)) = (
        maybe_total_logs,
        maybe_total_alerts,
        maybe_active_alerts,
        maybe_critical_alerts,
    ) {
        return HttpResponse::Ok().json(serde_json::json!({
            "tenant_id": claims.tenant_id,
            "total_logs": total_logs,
            "total_alerts": total_alerts,
            "active_alerts": active_alerts,
            "critical_alerts": critical_alerts,
        }));
    }

    // Fallback: use persisted snapshot for this tenant if available.
    match state.db.get_stats(&claims.tenant_id).await {
        Ok((total_logs, total_alerts, active_alerts, critical_alerts)) => {
            // Best-effort: seed Redis counters so L1/cache path picks them up quickly.
            let _ = state.redis.set_counter(&format!("{}:total_logs", tenant_prefix), total_logs as u64, Some(86400)).await;
            let _ = state.redis.set_counter(&format!("{}:total_alerts", tenant_prefix), total_alerts as u64, Some(86400)).await;
            let _ = state.redis.set_counter(&format!("{}:active_alerts", tenant_prefix), active_alerts as u64, Some(86400)).await;
            let _ = state.redis.set_counter(&format!("{}:critical_alerts", tenant_prefix), critical_alerts as u64, Some(86400)).await;

            HttpResponse::Ok().json(serde_json::json!({
                "tenant_id": claims.tenant_id,
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
