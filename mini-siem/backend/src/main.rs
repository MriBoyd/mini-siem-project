use actix_web::web;
use tokio::{signal, task, sync::{broadcast, mpsc}};
use tracing::{info, error};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use metrics_exporter_prometheus::PrometheusBuilder;
use metrics::{gauge, register_gauge};

mod api;
mod types;
mod detection;
mod db;
mod alerting;
mod queue;
mod config;
mod auth;

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
    
    // Load configuration
    let cfg = config::Config::from_env()?;
    let database_url = cfg.database_url.clone();
    let redis_url = cfg.redis_url.clone();
    let kafka_brokers = cfg.kafka_brokers.clone();
    let slack_webhook = cfg.slack_webhook.clone();

    info!("✅ Configuration loaded. Connecting to database and message brokers...");

    
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
    let detection_engine = detection::DetectionEngine::new(alert_tx.clone(), redis.clone(), db.clone()).await;
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
    let log_channel_full_counter = std::sync::Arc::new(AtomicUsize::new(0));
    // Start Prometheus metrics exporter (optional)
    match cfg.metrics_bind.parse::<std::net::SocketAddr>() {
        Ok(addr) => {
            if let Err(e) = PrometheusBuilder::new().with_http_listener(addr).install() {
                error!("failed to install Prometheus recorder: {}", e);
            }
        }
        Err(e) => {
            error!("invalid METRICS_BIND address {}: {}", cfg.metrics_bind, e);
        }
    }

    // Register a gauge metric for dropped logs
    register_gauge!("siem_log_channel_drops");

    // Spawn a task to periodically update the Prometheus gauge from the atomic counter
    let metrics_counter = log_channel_full_counter.clone();
    let _metrics_handle = task::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            let val = metrics_counter.load(std::sync::atomic::Ordering::Relaxed) as f64;
            gauge!("siem_log_channel_drops", val);
        }
    });
    let kafka_handle = {
        let counter = log_channel_full_counter.clone();
        task::spawn(async move {
            tokio::select! {
                res = kafka_consumer.consume_logs(log_tx_clone, Some(counter)) => {
                    if let Err(e) = res {
                        error!("Kafka consumer error: {}", e);
                    }
                }
                _ = kafka_shutdown_rx.recv() => {
                    info!("🛑 Kafka consumer received shutdown");
                }
            }
        })
    };
    
    // Create shared application state for the API handlers.
    let app_state = web::Data::new(api::server::AppState {
        db: db.clone(),
        redis: redis.clone(),
        kafka: kafka.clone(),
        log_tx: log_tx.clone(),
    });

    info!("✅ Mini SIEM fully initialized");
    info!("📡 API: http://{}", cfg.api_bind);
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
    let ctrl_c_fut = async {
        if let Err(e) = signal::ctrl_c().await {
            error!("failed to install Ctrl+C handler: {}", e);
        }
    };

    let mut sigterm: Option<tokio::signal::unix::Signal> = {
        #[cfg(unix)]
        {
            match signal::unix::signal(signal::unix::SignalKind::terminate()) {
                Ok(s) => Some(s),
                Err(e) => {
                    error!("failed to install unix signal handler: {}", e);
                    None
                }
            }
        }
        #[cfg(not(unix))]
        {
            None
        }
    };

    let sigterm_fut = async {
        if let Some(s) = sigterm.as_mut() {
            s.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    tokio::select! {
        _ = ctrl_c_fut => {},
        _ = sigterm_fut => {},
    }
}