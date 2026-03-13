use actix_web::web;
use anyhow::Context;
use tokio::{signal, task, sync::{broadcast, mpsc}};
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
    let database_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL must be set")?;
    let redis_url = std::env::var("REDIS_URL")
        .context("REDIS_URL must be set")?;
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
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    
    // Start detection engine
    let detection_engine = detection::DetectionEngine::new(alert_tx.clone(), redis, db.clone()).await;
    let mut detect_shutdown_rx = shutdown_tx.subscribe();
    let detection_handle = task::spawn(async move {
        loop {
            tokio::select! {
                Some(log) = log_rx.recv() => {
                    detection_engine.process_log(log).await;
                }
                _ = detect_shutdown_rx.recv() => {
                    info!("🛑 Detection engine received shutdown");
                    break;
                }
            }
        }
    });
    
    // Start alert handler with Slack
    let mut alert_shutdown_rx = shutdown_tx.subscribe();
    let alert_handle = task::spawn(async move {
        loop {
            tokio::select! {
                Some(alert) = alert_rx.recv() => {
                    info!("📢 Alert: {} - {}", alert.severity, alert.description);
                    
                    // Send to Slack
                    if let Err(e) = slack.send_alert(&alert).await {
                        error!("Failed to send Slack notification: {}", e);
                    }
                }
                _ = alert_shutdown_rx.recv() => {
                    info!("🛑 Alert handler received shutdown");
                    break;
                }
            }
        }
    });
    
    // Start Kafka consumer (receives logs from Go agent)
    let kafka_consumer = kafka.clone();
    let log_tx_clone = log_tx.clone();
    let mut kafka_shutdown_rx = shutdown_tx.subscribe();
    let kafka_handle = task::spawn(async move {
        tokio::select! {
            res = kafka_consumer.consume_logs(log_tx_clone) => {
                if let Err(e) = res {
                    error!("Kafka consumer error: {}", e);
                }
            }
            _ = kafka_shutdown_rx.recv() => {
                info!("🛑 Kafka consumer received shutdown");
            }
        }
    });
    
    // Create shared application state for the API handlers.
    let app_state = web::Data::new(api::server::AppState {
        db: db.clone(),
        kafka: kafka.clone(),
    });

    info!("✅ Mini SIEM fully initialized");
    info!("📡 API: http://localhost:8080");
    info!("📊 Kafka: {}", kafka_brokers);
    info!("💾 PostgreSQL: connected");
    info!("🗄️  Redis: connected");
    info!("📢 Slack: {}", if slack_url_copy.is_some() { "enabled" } else { "disabled" });
    info!("🔄 Go Agent integration: ready");
    info!("📋 Press Ctrl+C to stop");

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

    info!("🛑 Shutting down...");

    // Notify background tasks to shutdown
    let _ = shutdown_tx.send(());

    // Await tasks (give them a moment to finish)
    let _ = detection_handle.await;
    let _ = alert_handle.await;
    let _ = kafka_handle.await;

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