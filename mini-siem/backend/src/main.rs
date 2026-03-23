use actix_web::web;
use tokio::{signal, task, sync::{broadcast, mpsc}};
use tracing::{info, error};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use mini_siem::db::PostgresDb;
use mini_siem::db::redis::RedisCache;
use mini_siem::db::cache::Cache;
use mini_siem::queue::kafka::KafkaQueue;
use mini_siem::response::engine::ResponseEngine;
use mini_siem::response::actions::WebhookAction;
use mini_siem::{api, types, detection, alerting, config};


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
    // Start L1 cache maintenance: evict entries older than 5 minutes every 60s,
    // refresh hot keys older than 30s, keep top 100 hot keys refreshed
    let _l1_maint = redis.start_l1_maintenance(60, 300, 30, 100);
    
    // Initialize Kafka
    let kafka: KafkaQueue = KafkaQueue::new(&kafka_brokers).await?;
    let kafka = Arc::new(kafka);
    
    // Initialize Slack notifier
    let slack_url_copy = slack_webhook.clone();
    let slack = Arc::new(alerting::notifiers::slack::SlackNotifier::new(slack_webhook.clone()));
    
    // Initialize Response Engine (SOAR)
    let response_engine = Arc::new(ResponseEngine::new());
    if let Some(webhook_url) = slack_webhook.clone() {
        // Automatically add a critical response policy to hit the webhook
        info!("🤖 Configuring Response Engine: Critical alerts will trigger Slack webhook");
        let action = Arc::new(WebhookAction::new("Critical Slack Hook", webhook_url));
        response_engine.add_severity_policy(mini_siem::types::AlertSeverity::Critical, action).await;
    }

    // Create channels
    let (log_tx, mut log_rx) = mpsc::channel::<std::sync::Arc<types::Log>>(10000);
    let (alert_tx, mut _alert_rx_old) = broadcast::channel::<types::Alert>(1000);
    // Broadcast channel for aggregated dashboard stats
    let (stats_tx, mut _stats_rx_old) = broadcast::channel::<types::DashboardStats>(100);
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    
    // Start detection engine
    let detection_engine = Arc::new(detection::engine::DetectionEngine::new(
        alert_tx.clone(),
        stats_tx.clone(),
        redis.clone(),
        db.clone(),
        response_engine.clone(),
        kafka.clone(),
    ).await);
    let mut detect_shutdown_rx = shutdown_tx.subscribe();
    let detection_engine_clone = detection_engine.clone();
    let detection_handle = task::spawn(async move {
        let mut reload_interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                Some(log) = log_rx.recv() => {
                    detection_engine_clone.process_log(log).await;
                }
                _ = reload_interval.tick() => {
                    if let Err(e) = detection_engine_clone.reload_rules().await {
                        error!("Failed to reload rules: {}", e);
                    }
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
    let mut alert_rx = alert_tx.subscribe();
    let alert_handle = task::spawn(async move {
        loop {
            tokio::select! {
                Ok(alert) = alert_rx.recv() => {
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
    // Start Prometheus exporter and monitoring
    if let Err(e) = mini_siem::monitoring::init_metrics(&cfg.metrics_bind) {
        error!("failed to start metrics exporter: {}", e);
    }

    // Spawn a task to periodically update the Prometheus gauge from the atomic counter
    let metrics_counter = log_channel_full_counter.clone();
    let _metrics_handle = task::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            let val = metrics_counter.load(std::sync::atomic::Ordering::Relaxed) as f64;
            metrics::gauge!("siem_log_channel_drops", val);
        }
    });
    let kafka_handle = {
        let counter = log_channel_full_counter.clone();
        let rl_per_ip = cfg.rate_limit_per_ip;
        let rl_window = cfg.rate_limit_window_ms;
        let rl_sample = cfg.rate_limit_sample_rate;
        let redis_for_consumer = redis.clone();
        task::spawn(async move {
            tokio::select! {
                res = kafka_consumer.consume_logs(log_tx_clone, Some(counter), cfg.kafka_pause_on_full, cfg.kafka_pause_timeout_ms, rl_per_ip, rl_window, rl_sample, redis_for_consumer) => {
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
        alert_tx: alert_tx.clone(),
        stats_tx: stats_tx.clone(),
    });

    // Start dedicated alert worker to process alerts from Kafka asynchronously
    // Create DB batcher channel and spawn the DB batcher
    let (db_tx, db_rx) = mpsc::channel::<types::Alert>(1000);
    let _db_batcher_handle = alerting::db_batcher::spawn_db_batcher(
        db.clone(),
        db_rx,
        shutdown_tx.subscribe(),
        100,
        1000,
    );

    let alert_worker_handle = alerting::worker::spawn_alert_worker(
        kafka.clone(),
        db.clone(),
        redis.clone(),
        response_engine.clone(),
        alert_tx.clone(),
        stats_tx.clone(),
        db_tx.clone(),
        shutdown_tx.subscribe(),
        cfg.kafka_pause_on_full,
        cfg.kafka_pause_timeout_ms,
    ).await;

    // Start periodic Redis -> Postgres stats sync (reads Redis counters and persists them periodically)
    let db_clone_for_stats = db.clone();
    let redis_clone_for_stats = redis.clone();
    let _stats_sync_handle = task::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            // best-effort: read counters from Redis
            let total_logs = redis_clone_for_stats.get_counter("siem:stats:total_logs").await.ok().flatten().map(|v| v as i64).unwrap_or(0);
            let total_alerts = redis_clone_for_stats.get_counter("siem:stats:total_alerts").await.ok().flatten().map(|v| v as i64).unwrap_or(0);
            let active_alerts = redis_clone_for_stats.get_counter("siem:stats:active_alerts").await.ok().flatten().map(|v| v as i64).unwrap_or(0);
            let critical_alerts = redis_clone_for_stats.get_counter("siem:stats:critical_alerts").await.ok().flatten().map(|v| v as i64).unwrap_or(0);

            if let Err(e) = db_clone_for_stats.save_stats(total_logs, total_alerts, active_alerts, critical_alerts).await {
                error!("Failed to persist aggregated stats to DB: {}", e);
            }
        }
    });

    info!("✅ Mini SIEM fully initialized");
    info!("📡 API: http://{}", cfg.api_bind);
    info!("📊 Kafka: {}", kafka_brokers);
    info!("💾 PostgreSQL: connected");
    info!("🗄️ Redis: connected");
    info!("📢 Slack: {}", if slack_url_copy.is_some() { "enabled" } else { "disabled" });
    info!("🔄 Go Agent integration: ready");
    info!("🤖 SOAR Engine: active");
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
    let _ = alert_worker_handle.await;

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