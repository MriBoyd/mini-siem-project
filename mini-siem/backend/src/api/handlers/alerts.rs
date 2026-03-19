use actix_web::{get, web, HttpResponse, Responder, HttpRequest, HttpMessage};

use crate::api::server::AppState;
use crate::auth::jwt::Claims;

#[get("/api/v1/alerts")]
pub async fn list_alerts(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    // RBAC: only users with 'analyst' or 'admin' roles may view alerts
    let exts = req.extensions();
    let claims = match exts.get::<Claims>() {
        Some(c) => c,
        None => return actix_web::error::ErrorUnauthorized("missing auth").error_response(),
    };

    let roles = &claims.roles;
    if !(roles.contains(&"analyst".to_string()) || roles.contains(&"admin".to_string())) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error":"insufficient role"}));
    }

    match state.db.get_recent_alerts(50).await {
        Ok(alerts) => HttpResponse::Ok().json(alerts),
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("failed to query alerts: {}", e),
            }))
        }
    }
}
