use actix_web::{web, App, HttpServer, middleware::Logger};
use actix_cors::Cors;
use tracing::info;

use crate::api::handlers::{logs, health, alerts, dashboard};

pub async fn run_server() -> std::io::Result<()> {
    // allow binding address to be configured via env var
    let bind_address = std::env::var("API_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    
    info!("🚀 Starting Mini SIEM API on http://{}", bind_address);
    
    HttpServer::new(|| {
        // Configure CORS
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header();
        
        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .service(health::root)
            .service(health::health_check)
            .service(logs::ingest_log)
            .service(logs::ingest_batch)
            .service(alerts::list_alerts)
            .service(dashboard::get_stats)
    })
    .bind(bind_address)?
    .run()
    .await
}