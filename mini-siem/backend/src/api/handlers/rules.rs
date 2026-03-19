use actix_web::{get, post, put, delete, web, HttpResponse, Responder};
use uuid::Uuid;
use crate::api::server::AppState;
use crate::db::models::rule::{RuleCreate, RuleUpdate};

#[get("/api/v1/rules")]
pub async fn list_rules(state: web::Data<AppState>) -> impl Responder {
    match state.db.get_all_rules().await {
        Ok(rules) => HttpResponse::Ok().json(rules),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Database error: {}", e)})),
    }
}

#[post("/api/v1/rules")]
pub async fn create_rule(
    state: web::Data<AppState>,
    req: web::Json<RuleCreate>,
) -> impl Responder {
    match state.db.create_rule(&req).await {
        Ok(rule) => HttpResponse::Created().json(rule),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Database error: {}", e)})),
    }
}

#[get("/api/v1/rules/{id}")]
pub async fn get_rule(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> impl Responder {
    let id = path.into_inner();
    match state.db.get_rule_by_id(id).await {
        Ok(Some(rule)) => HttpResponse::Ok().json(rule),
        Ok(None) => HttpResponse::NotFound().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Database error: {}", e)})),
    }
}

#[put("/api/v1/rules/{id}")]
pub async fn update_rule(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
    req: web::Json<RuleUpdate>,
) -> impl Responder {
    let id = path.into_inner();
    match state.db.update_rule(id, req.into_inner()).await {
        Ok(rule) => HttpResponse::Ok().json(rule),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Database error: {}", e)})),
    }
}

#[delete("/api/v1/rules/{id}")]
pub async fn delete_rule(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> impl Responder {
    let id = path.into_inner();
    match state.db.delete_rule(id).await {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Database error: {}", e)})),
    }
}

#[post("/api/v1/rules/{id}/toggle")]
pub async fn toggle_rule(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> impl Responder {
    let id = path.into_inner();
    match state.db.get_rule_by_id(id).await {
        Ok(Some(rule)) => {
            let update = RuleUpdate {
                name: None,
                description: None,
                severity: None,
                threshold: None,
                window_seconds: None,
                is_enabled: Some(!rule.is_enabled),
            };
            match state.db.update_rule(id, update).await {
                Ok(updated) => HttpResponse::Ok().json(updated),
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Database error: {}", e)})),
            }
        },
        Ok(None) => HttpResponse::NotFound().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Database error: {}", e)})),
    }
}
