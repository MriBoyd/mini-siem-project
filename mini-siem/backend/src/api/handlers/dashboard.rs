use actix_web::{get, HttpResponse, Responder};

#[derive(serde::Serialize)]
struct DashboardStats {
    total_logs: usize,
    total_alerts: usize,
    active_alerts: usize,
    critical_alerts: usize,
}

#[get("/api/v1/dashboard/stats")]
pub async fn get_stats() -> impl Responder {
    // TODO: Replace with real statistics from the database.
    let stats = DashboardStats {
        total_logs: 1_234,
        total_alerts: 12,
        active_alerts: 4,
        critical_alerts: 2,
    };

    HttpResponse::Ok().json(stats)
}
