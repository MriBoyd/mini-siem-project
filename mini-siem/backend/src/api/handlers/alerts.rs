use actix_web::{get, web, HttpResponse, Responder, HttpRequest};

use crate::api::server::AppState;
use crate::auth::jwt::JwtConfig;

fn extract_claims_from_request(req: &HttpRequest) -> Result<crate::auth::jwt::Claims, actix_web::Error> {
    let jwt = req.app_data::<web::Data<JwtConfig>>().cloned().ok_or_else(|| actix_web::error::ErrorInternalServerError("JWT config missing"))?;
    let header = req.headers().get("Authorization").and_then(|h| h.to_str().ok()).ok_or_else(|| actix_web::error::ErrorUnauthorized("missing auth header"))?;
    if !header.starts_with("Bearer ") { return Err(actix_web::error::ErrorUnauthorized("invalid auth header")); }
    let token = header.trim_start_matches("Bearer ").trim();
    let data = jwt.verify_access_token(token).map_err(|_| actix_web::error::ErrorUnauthorized("invalid token"))?;
    Ok(data.claims)
}

#[get("/api/v1/alerts")]
pub async fn list_alerts(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    // RBAC: only users with 'analyst' or 'admin' roles may view alerts
    let claims = match extract_claims_from_request(&req) {
        Ok(c) => c,
        Err(e) => return e.error_response(),
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
