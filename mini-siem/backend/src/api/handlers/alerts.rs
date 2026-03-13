use actix_web::{get, web, HttpResponse, Responder};

use crate::api::server::AppState;

#[get("/api/v1/alerts")]
pub async fn list_alerts(state: web::Data<AppState>) -> impl Responder {
    match state.db.get_recent_alerts(50).await {
        Ok(alerts) => HttpResponse::Ok().json(alerts),
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("failed to query alerts: {}", e),
            }))
        }
    }
}
