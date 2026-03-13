use actix_web::web;
use tokio::{signal, task, sync::mpsc};
use tracing::{info, error};
use tracing_subscriber;
use std::sync::Arc;

mod api;
mod types;
mod detection;
mod db;
mod alerting;
mod queue;

use db::{PostgresDb};
use db::redis::RedisCache;
use queue::kafka::KafkaQueue;


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();
    
    info!("🚀 Starting Mini SIEM (Rust Edition) v{}", env!("CARGO_PKG_VERSION"));
    
    // Load environment
    dotenvy::dotenv().ok();
    
    // Get configuration from environment
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");
    let kafka_brokers = std::env::var("KAFKA_BROKERS").unwrap_or_else(|_| "localhost:9092".to_string());
    let slack_webhook = std::env::var("SLACK_WEBHOOK").ok();
    
    // Initialize database
    let db = Arc::new(PostgresDb::new(&database_url).await?);
    
    // Initialize Redis
    let redis = RedisCache::new(&redis_url).await?;
    
    // Initialize Kafka
    let kafka: KafkaQueue = KafkaQueue::new(&kafka_brokers).await?;
    let kafka = Arc::new(kafka);
    
    // Initialize Slack notifier
    let slack_url_copy = slack_webhook.clone();
    let slack = Arc::new(alerting::notifiers::slack::SlackNotifier::new(slack_webhook.clone()));
    
    // Create channels
    let (log_tx, mut log_rx) = mpsc::channel::<types::Log>(10000);
    let (alert_tx, mut alert_rx) = mpsc::channel::<types::Alert>(1000);
    
    // Start detection engine
    let detection_engine = detection::DetectionEngine::new(alert_tx.clone(), redis, db.clone()).await;
    
    let detection_handle = task::spawn(async move {
        while let Some(log) = log_rx.recv().await {
            detection_engine.process_log(log).await;
        }
    });
    
    // Start alert handler with Slack
    let alert_handle = task::spawn(async move {
        while let Some(alert) = alert_rx.recv().await {
            info!("📢 Alert: {} - {}", alert.severity, alert.description);
            
            // Send to Slack
            if let Err(e) = slack.send_alert(&alert).await {
                error!("Failed to send Slack notification: {}", e);
            }
        }
    });
    
    // Start Kafka consumer (receives logs from Go agent)
    let kafka_consumer = kafka.clone();
    let log_tx_clone = log_tx.clone();
    let kafka_handle = task::spawn(async move {
        if let Err(e) = kafka_consumer.consume_logs(log_tx_clone).await {
            error!("Kafka consumer error: {}", e);
        }
    });
    
    // Create shared application state for the API handlers.
    let app_state = web::Data::new(api::server::AppState {
        db: db.clone(),
        kafka: kafka.clone(),
    });

    // Run API server until shutdown signal or error
    tokio::select! {
        res = api::run_server(app_state) => {
            if let Err(e) = res {
                // If the address is in use, log a clearer message
                if e.kind() == std::io::ErrorKind::AddrInUse {
                    error!("API bind address in use - is another instance running?");
                }
                error!("Server error: {}", e);
            }
        }
        _ = shutdown_signal() => {}
    }
    
    info!("✅ Mini SIEM fully initialized");
    info!("📡 API: http://localhost:8080");
    info!("📊 Kafka: {}", kafka_brokers);
    info!("💾 PostgreSQL: connected");
    info!("🗄️  Redis: connected");
    info!("📢 Slack: {}", if slack_url_copy.is_some() { "enabled" } else { "disabled" });
    info!("🔄 Go Agent integration: ready");
    info!("📋 Press Ctrl+C to stop");
    
    // Wait for shutdown signal
    shutdown_signal().await;
    
    info!("🛑 Shutting down...");
    
    // Cancel tasks
    detection_handle.abort();
    alert_handle.abort();
    kafka_handle.abort();
    
    info!("👋 Goodbye!");
    
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}