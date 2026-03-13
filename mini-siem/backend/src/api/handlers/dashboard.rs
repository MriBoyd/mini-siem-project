use actix_web::{get, web, HttpResponse, Responder};

use crate::api::server::AppState;

#[get("/api/v1/dashboard/stats")]
pub async fn get_stats(state: web::Data<AppState>) -> impl Responder {
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
