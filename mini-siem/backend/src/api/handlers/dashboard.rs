use actix_web::{get, web, HttpResponse, Responder, HttpRequest, HttpMessage};

use crate::api::server::AppState;
use crate::auth::jwt::Claims;

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

    match state.db.get_stats().await {
        Ok((total_logs, total_alerts, active_alerts, critical_alerts)) => {
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
