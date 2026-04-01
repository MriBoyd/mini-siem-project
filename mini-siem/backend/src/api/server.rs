use actix_web::{web, App, HttpServer, middleware::Logger, http::header};
use actix_cors::Cors;
use tracing::info;
use std::sync::Arc;
use tokio::sync::{mpsc, broadcast};

use crate::api::handlers::{logs, health, alerts, dashboard, auth, rules};
use crate::api::middleware::auth::JwtAuth;
use crate::db::PostgresDb;
use crate::db::redis::RedisCache;
use crate::queue::kafka::KafkaQueue;
use crate::types::{Log, Alert};
use crate::db::ElasticClient;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<PostgresDb>,
    pub redis: RedisCache,
    pub kafka: Arc<KafkaQueue>,
    pub ingest_tx: mpsc::Sender<std::sync::Arc<Log>>,
    pub log_tx: mpsc::Sender<std::sync::Arc<Log>>,
    pub alert_tx: broadcast::Sender<Alert>,
    pub stats_tx: broadcast::Sender<crate::types::DashboardStats>,
    pub elastic: tokio::sync::watch::Receiver<Option<Arc<ElasticClient>>>,
}

pub async fn run_server(state: web::Data<AppState>, cors_allowed_origins: Vec<String>) -> std::io::Result<()> {
    // allow binding address to be configured via env var
    let bind_address = std::env::var("API_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    
    info!("🚀 Starting Mini SIEM API on http://{}", bind_address);
    
    HttpServer::new(move || {
        // Configure CORS for trusted browser clients only.
        let mut cors = Cors::default()
            .supports_credentials()
            .allowed_methods(vec!["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
            .allowed_header(header::AUTHORIZATION)
            .allowed_header(header::ACCEPT)
            .allowed_header(header::CONTENT_TYPE)
            .allowed_header(header::HeaderName::from_static("x-ws-token"))
            .allowed_header(header::HeaderName::from_static("sec-websocket-protocol"));

        for origin in &cors_allowed_origins {
            cors = cors.allowed_origin(origin.as_str());
        }
        
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
                    .service(auth::ws_token)
                    .service(
                        web::scope("")
                            .wrap(JwtAuth)
                            .service(auth::me)
                    )
                    .service(auth::refresh)
                    .service(auth::logout)
            )
            // Logs are tenant-scoped and require authentication.
            .service(
                web::scope("")
                    .wrap(JwtAuth)
                    .service(logs::ingest_log)
                    .service(logs::ingest_batch)
                    .service(logs::recent_logs)
            )

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
                    .service(web::resource("/ws/alerts").route(web::get().to(alerts::ws_alerts)))
            )
    })
    .bind(bind_address)?
    .run()
    .await
}