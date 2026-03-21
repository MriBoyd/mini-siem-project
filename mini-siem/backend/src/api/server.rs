use actix_web::{web, App, HttpServer, middleware::Logger};
use actix_cors::Cors;
use tracing::info;
use std::sync::Arc;

use crate::api::handlers::{logs, health, alerts, dashboard, auth, rules};
use crate::api::middleware::auth::JwtAuth;
use crate::db::PostgresDb;
use crate::db::redis::RedisCache;
use crate::queue::kafka::KafkaQueue;
use tokio::sync::mpsc;
use crate::types::Log;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<PostgresDb>,
    pub redis: RedisCache,
    pub kafka: Arc<KafkaQueue>,
    pub log_tx: mpsc::Sender<Log>,
}

pub async fn run_server(state: web::Data<AppState>) -> std::io::Result<()> {
    // allow binding address to be configured via env var
    let bind_address = std::env::var("API_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    
    info!("🚀 Starting Mini SIEM API on http://{}", bind_address);
    
    HttpServer::new(move || {
        // Configure CORS
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header();
        
        App::new()
            .app_data(state.clone())
            .wrap(Logger::default())
            .wrap(cors)
            .service(health::root)
            .service(health::health_check)
            // Public auth routes (logout requires JWT for revoking, but the handler will check it)
            // Actually, logout should be protected so we know WHICH user's token to revoke, 
            // OR we just revoke the refresh token provided. The current logout handler revokes 
            // the provided refresh token. Let's make it public but optionally take JWT.
            .service(
                web::scope("/api/v1/auth")
                    .service(auth::register)
                    .service(auth::login)
                    .service(auth::me)
                    .service(auth::refresh)
                    .service(auth::logout)
            )
            // Public logs ingest endpoints (register before the protected scope)
            .service(logs::ingest_log)
            .service(logs::ingest_batch)

            // Protected routes
            .service(
                web::scope("/api/v1")
                    .wrap(JwtAuth)
                    .service(alerts::list_alerts)
                    .service(dashboard::get_stats)
                    .service(rules::list_rules)
                    .service(rules::create_rule)
                    .service(rules::get_rule)
                    .service(rules::update_rule)
                    .service(rules::delete_rule)
                    .service(rules::toggle_rule)
            )
    })
    .bind(bind_address)?
    .run()
    .await
}