use actix_web::{get, post, put, delete, web, HttpResponse, Responder, HttpRequest, HttpMessage};
use uuid::Uuid;
use crate::api::server::AppState;
use crate::auth::jwt::Claims;
use crate::db::models::rule::{RuleCreate, RuleUpdate};

#[get("/rules")]
pub async fn list_rules(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    let claims = match req.extensions().get::<Claims>() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    match state.db.get_all_rules(&claims.tenant_id).await {
        Ok(rules) => HttpResponse::Ok().json(rules),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Database error: {}", e)})),
    }
}

#[post("/rules")]
pub async fn create_rule(
    http_req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<RuleCreate>,
) -> impl Responder {
    let claims = match http_req.extensions().get::<Claims>() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    let mut rule = body.into_inner();
    rule.tenant_id = claims.tenant_id.clone();

    match state.db.create_rule(&rule).await {
        Ok(rule) => HttpResponse::Created().json(rule),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Database error: {}", e)})),
    }
}

#[get("/rules/{id}")]
pub async fn get_rule(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> impl Responder {
    let claims = match req.extensions().get::<Claims>() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    let id = path.into_inner();
    match state.db.get_rule_by_id(&claims.tenant_id, id).await {
        Ok(Some(rule)) => HttpResponse::Ok().json(rule),
        Ok(None) => HttpResponse::NotFound().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Database error: {}", e)})),
    }
}

#[put("/rules/{id}")]
pub async fn update_rule(
    http_req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
    body: web::Json<RuleUpdate>,
) -> impl Responder {
    let claims = match http_req.extensions().get::<Claims>() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    let id = path.into_inner();
    match state.db.update_rule(&claims.tenant_id, id, body.into_inner()).await {
        Ok(rule) => HttpResponse::Ok().json(rule),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Database error: {}", e)})),
    }
}

#[delete("/rules/{id}")]
pub async fn delete_rule(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> impl Responder {
    let claims = match req.extensions().get::<Claims>() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    let id = path.into_inner();
    match state.db.delete_rule(&claims.tenant_id, id).await {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Database error: {}", e)})),
    }
}

#[post("/rules/{id}/toggle")]
pub async fn toggle_rule(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> impl Responder {
    let claims = match req.extensions().get::<Claims>() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    let id = path.into_inner();
    match state.db.get_rule_by_id(&claims.tenant_id, id).await {
        Ok(Some(rule)) => {
            let update = RuleUpdate {
                name: None,
                description: None,
                severity: None,
                threshold: None,
                window_seconds: None,
                condition: None,
                is_enabled: Some(!rule.is_enabled),
            };
            match state.db.update_rule(&claims.tenant_id, id, update).await {
                Ok(updated) => HttpResponse::Ok().json(updated),
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Database error: {}", e)})),
            }
        },
        Ok(None) => HttpResponse::NotFound().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Database error: {}", e)})),
    }
}
