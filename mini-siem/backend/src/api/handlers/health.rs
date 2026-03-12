use actix_web::{get, HttpResponse, Responder};

#[get("/health")]
pub async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// root endpoint, useful for browsers hitting `/`
#[get("/")]
pub async fn root() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Mini SIEM API is running",
        "health": "/health"
    }))
}