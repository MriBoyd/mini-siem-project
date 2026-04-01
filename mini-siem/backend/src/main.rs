use actix_web::web;
use tokio::{signal, task, sync::{broadcast, mpsc, watch}};
use tracing::{info, error};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::hash::{Hash, Hasher};
use mini_siem::db::PostgresDb;
use mini_siem::db::redis::RedisCache;
use mini_siem::db::cache::Cache;
use mini_siem::queue::kafka::KafkaQueue;
use mini_siem::response::engine::ResponseEngine;
use mini_siem::response::actions::WebhookAction;
use mini_siem::{api, types, detection, alerting, config, auth};
use rustc_hash::FxHasher;
use std::time::{Duration, Instant};
use chrono::Utc;

struct ManagedTask {
    name: &'static str,
    handle: tokio::task::JoinHandle<()>,
}

#[derive(Default)]
struct TaskRegistry {
    tasks: Vec<ManagedTask>,
}

impl TaskRegistry {
    fn push(&mut self, name: &'static str, handle: tokio::task::JoinHandle<()>) {
        self.tasks.push(ManagedTask { name, handle });
    }

    async fn drain(mut self, grace_period: Duration) {
        let deadline = Instant::now() + grace_period;

        for mut task in self.tasks.drain(..) {
            let now = Instant::now();
            if now >= deadline {
                task.handle.abort();
                let _ = task.handle.await;
                tracing::warn!(task = task.name, "Aborted background task after shutdown deadline");
                continue;
            }

            let remaining = deadline.saturating_duration_since(now);
            match tokio::time::timeout(remaining, &mut task.handle).await {
                Ok(Ok(())) => {
                    tracing::info!(task = task.name, "Background task shut down cleanly");
                }
                Ok(Err(join_error)) => {
                    tracing::warn!(task = task.name, error = %join_error, "Background task ended with join error");
                }
                Err(_) => {
                    task.handle.abort();
                    let _ = task.handle.await;
                    tracing::warn!(task = task.name, "Aborted background task after drain timeout");
                }
            }
        }
    }
}

async fn final_stats_checkpoint(db: &Arc<PostgresDb>, redis: &RedisCache) {
    let total_logs = redis.get_counter("siem:stats:total_logs").await.ok().flatten().map(|v| v as i64).unwrap_or(0);
    let total_alerts = redis.get_counter("siem:stats:total_alerts").await.ok().flatten().map(|v| v as i64).unwrap_or(0);
    let active_alerts = redis.get_counter("siem:stats:active_alerts").await.ok().flatten().map(|v| v as i64).unwrap_or(0);
    let critical_alerts = redis.get_counter("siem:stats:critical_alerts").await.ok().flatten().map(|v| v as i64).unwrap_or(0);

    if let Err(e) = db.save_stats("", total_logs, total_alerts, active_alerts, critical_alerts).await {
        error!("Failed to persist final stats checkpoint: {}", e);
    } else {
        info!("✅ Final stats checkpoint persisted");
    }
}

async fn run_tenant_retention_cycle(
    db: &Arc<PostgresDb>,
    elastic: &tokio::sync::watch::Receiver<Option<Arc<mini_siem::db::ElasticClient>>>,
    elastic_index: &str,
) {
    let policies = match db.list_tenant_compliance_policies().await {
        Ok(policies) => policies,
        Err(e) => {
            error!("Failed to load tenant compliance policies: {}", e);
            return;
        }
    };

    for policy in policies {
        let hold_active = if policy.legal_hold {
            if let Some(until) = policy.legal_hold_until {
                until > Utc::now()
            } else {
                true
            }
        } else {
            false
        };

        if hold_active {
            continue;
        }

        let retention_days = policy.retention_days.max(1) as i64;
        let cutoff = Utc::now() - chrono::Duration::days(retention_days);

        if let Err(e) = db.purge_audit_events_before(&policy.tenant_id, cutoff).await {
            error!(tenant = %policy.tenant_id, "Failed to purge old audit events: {}", e);
        }

        if let Err(e) = db.purge_alerts_before(&policy.tenant_id, cutoff).await {
            error!(tenant = %policy.tenant_id, "Failed to purge old alerts: {}", e);
        }

        let elastic_client = { elastic.borrow().clone() };
        if let Some(elastic_client) = elastic_client {
            let query = serde_json::json!({
                "bool": {
                    "filter": [
                        { "term": { "tenant_id": policy.tenant_id } },
                        { "range": { "@timestamp": { "lt": cutoff.to_rfc3339() } } }
                    ]
                }
            });
            if let Err(e) = elastic_client.delete_by_query(elastic_index, query).await {
                error!(tenant = %policy.tenant_id, "Failed to purge old indexed logs: {}", e);
            }
        }
    }
}


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing + structured logs before any startup events.
    let observability = mini_siem::monitoring::init_tracing("mini-siem-backend")?;
    
    info!("🚀 Starting Mini SIEM (Rust Edition) v{}", env!("CARGO_PKG_VERSION"));
    
    // Load configuration
    let cfg = config::Config::from_env()?;
    let database_url = cfg.database_url.clone();
    let redis_url = cfg.redis_url.clone();
    let kafka_brokers = cfg.kafka_brokers.clone();
    let slack_webhook = cfg.slack_webhook.clone();
    let detection_workers = cfg.detection_workers.max(1);
    let detection_mailbox_size = cfg.detection_mailbox_size.max(1);
    let detection_partition_key = cfg.detection_partition_key.clone();
    let kafka_lag_sample_interval_secs = cfg.kafka_lag_sample_interval_secs.max(1);
    let kafka_lag_watermark_timeout_ms = cfg.kafka_lag_watermark_timeout_ms.max(1);
    let tenant_limits = cfg.tenant_limits();
    let audit_signing_key = cfg.audit_signing_key.clone();
    mini_siem::monitoring::set_tenant_label_limit(cfg.metrics_max_tenant_labels);

    info!("✅ Configuration loaded. Connecting to database and message brokers...");

    
    // Initialize database
    let db = Arc::new(PostgresDb::new(&database_url).await?);

    // Warm and periodically refresh the JWKS cache when external verification keys are used.
    let mut task_registry = TaskRegistry::default();

    if let Some(handle) = auth::jwt::spawn_jwks_refresh_task() {
        task_registry.push("jwks_refresh", handle);
    }
    
    // Initialize Redis
    let redis = RedisCache::new(&redis_url).await?;
    // Start L1 cache maintenance: evict entries older than 5 minutes every 60s,
    // refresh hot keys older than 30s, keep top 100 hot keys refreshed
    task_registry.push("l1_maintenance", redis.start_l1_maintenance(60, 300, 30, 100));
    
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
        response_engine.add_global_severity_policy(mini_siem::types::AlertSeverity::Critical, action).await;
    }

    // Create channels
    let (log_tx, mut log_rx) = mpsc::channel::<std::sync::Arc<types::Log>>(10000);
    let (ingest_tx, ingest_rx) = mpsc::channel::<std::sync::Arc<types::Log>>(10000);
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
    info!("🧠 Detection worker pool: {} workers, mailbox size {}", detection_workers, detection_mailbox_size);
    info!("🧠 Detection partition key: {}", detection_partition_key);
    info!("📈 Kafka lag sampling: every {}s, watermark timeout {}ms", kafka_lag_sample_interval_secs, kafka_lag_watermark_timeout_ms);

    let mut detection_worker_senders = Vec::with_capacity(detection_workers);
    for worker_id in 0..detection_workers {
        let (worker_tx, mut worker_rx) = mpsc::channel::<std::sync::Arc<types::Log>>(detection_mailbox_size);
        detection_worker_senders.push(worker_tx);

        let engine = detection_engine.clone();
        let mut worker_shutdown_rx = shutdown_tx.subscribe();
        let worker_handle = task::spawn(async move {
            loop {
                tokio::select! {
                    Some(log) = worker_rx.recv() => {
                        metrics::gauge!(
                            "siem_detection_worker_mailbox_depth",
                            worker_rx.len() as f64,
                            "worker" => worker_id.to_string()
                        );
                        engine.process_log(log).await;
                    }
                    _ = worker_shutdown_rx.recv() => {
                        info!("🛑 Detection worker {} received shutdown", worker_id);
                        break;
                    }
                }
            }
        });
        task_registry.push("detection_worker", worker_handle);
    }

    let mut detect_shutdown_rx = shutdown_tx.subscribe();
    let detection_dispatch_handle = {
        let detection_worker_senders = detection_worker_senders;
        task::spawn(async move {
            loop {
                tokio::select! {
                    Some(log) = log_rx.recv() => {
                        let worker_idx = detection_partition_index(&log, detection_worker_senders.len(), &detection_partition_key);
                        let dispatch_start = std::time::Instant::now();
                        if let Err(e) = detection_worker_senders[worker_idx].send(log).await {
                            error!("Detection worker {} mailbox closed: {}", worker_idx, e);
                            metrics::counter!("siem_detection_dispatch_failures_total", 1, "worker" => worker_idx.to_string());
                        } else {
                            let sender = &detection_worker_senders[worker_idx];
                            let depth = (sender.max_capacity().saturating_sub(sender.capacity())) as f64;
                            metrics::gauge!("siem_detection_worker_mailbox_depth", depth, "worker" => worker_idx.to_string());
                            metrics::histogram!("siem_detection_dispatch_wait_seconds", dispatch_start.elapsed().as_secs_f64(), "worker" => worker_idx.to_string());
                        }
                    }
                    _ = detect_shutdown_rx.recv() => {
                        info!("🛑 Detection dispatcher received shutdown");
                        break;
                    }
                }
            }
        })
    };
    task_registry.push("detection_dispatch", detection_dispatch_handle);

    let detection_engine_for_reload = detection_engine.clone();
    let mut reload_shutdown_rx = shutdown_tx.subscribe();
    let detection_reload_handle = task::spawn(async move {
        let mut reload_interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = reload_interval.tick() => {
                    if let Err(e) = detection_engine_for_reload.reload_rules().await {
                        error!("Failed to reload rules: {}", e);
                    }
                }
                _ = reload_shutdown_rx.recv() => {
                    info!("🛑 Detection rule reloader received shutdown");
                    break;
                }
            }
        }
    });
    task_registry.push("detection_reload", detection_reload_handle);
    
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
    task_registry.push("alert_handler", alert_handle);
    
    // Start Kafka consumer (receives logs from Go agent)
    let kafka_consumer = kafka.clone();
    let redis_for_indexer = redis.clone();
    let log_tx_clone = log_tx.clone();
    // Indexer channel and Elasticsearch client
    let (index_tx, mut index_rx) = mpsc::channel::<std::sync::Arc<types::Log>>(10000);
    let elastic_host = cfg.elasticsearch_host.clone();
    let elastic_index = cfg.elasticsearch_index.clone();
    let (elastic_tx, elastic_rx) = watch::channel::<Option<Arc<mini_siem::db::ElasticClient>>>(None);
    match mini_siem::db::ElasticClient::new(&elastic_host).await {
        Ok(c) => {
            let client = Arc::new(c);
            let _ = elastic_tx.send(Some(client));
            info!("✅ Elasticsearch connected: indexing enabled");
        }
        Err(e) => {
            error!("Failed to connect to Elasticsearch at startup, continuing with indexing disabled: {}", e);
        }
    }
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
        let index_tx_clone = index_tx.clone();
        task::spawn(async move {
            tokio::select! {
                res = kafka_consumer.consume_logs(log_tx_clone, Some(index_tx_clone), Some(counter), cfg.kafka_pause_on_full, cfg.kafka_pause_timeout_ms, rl_per_ip, rl_window, rl_sample, redis_for_consumer) => {
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
    task_registry.push("kafka_consumer", kafka_handle);
    let kafka_lag_metrics_handle = kafka.spawn_partition_lag_metrics_task(kafka_lag_sample_interval_secs, kafka_lag_watermark_timeout_ms);
    task_registry.push("kafka_lag_metrics", kafka_lag_metrics_handle);

    let kafka_ingest_handle = {
        let kafka = kafka.clone();
        let mut ingest_shutdown_rx = shutdown_tx.subscribe();
        let mut ingest_rx = ingest_rx;
        task::spawn(async move {
            loop {
                tokio::select! {
                    Some(log) = ingest_rx.recv() => {
                        if let Err(e) = kafka.send_log(&log).await {
                            error!("Failed to enqueue log to Kafka: {}", e);
                        }
                    }
                    _ = ingest_shutdown_rx.recv() => {
                        info!("🛑 Kafka ingest producer received shutdown");
                        while let Ok(log) = ingest_rx.try_recv() {
                            if let Err(e) = kafka.send_log(&log).await {
                                error!("Failed to drain log to Kafka during shutdown: {}", e);
                            }
                        }
                        break;
                    }
                }
            }
        })
    };
    task_registry.push("kafka_ingest", kafka_ingest_handle);

    // Spawn Elasticsearch indexer worker: batch documents for bulk indexing
    let mut elastic_rx_for_indexer = elastic_rx.clone();
    let idx = elastic_index.clone();
    let kafka_for_indexer = kafka.clone();
    let mut es_shutdown_rx = shutdown_tx.subscribe();
    let es_handle = task::spawn(async move {
        use tokio::time::{timeout, sleep, Duration};
        use mini_siem::queue::kafka::LOGS_DLQ_TOPIC;

        let mut buffer: Vec<std::sync::Arc<types::Log>> = Vec::with_capacity(1024);
        let batch_size = 500usize;
        let max_wait = Duration::from_millis(1000);
        let max_retries = 3usize;
        let mut backoff_ms = 500u64;

        loop {
            // wait for first item
            match index_rx.recv().await {
                Some(l) => buffer.push(l),
                None => break, // channel closed
            }

            // drain until batch_size or timeout
            loop {
                if buffer.len() >= batch_size {
                    break;
                }
                match timeout(max_wait, index_rx.recv()).await {
                    Ok(Some(l)) => buffer.push(l),
                    Ok(None) => break,
                    Err(_) => break, // timed out
                }
            }

            if buffer.is_empty() {
                continue;
            }

            // prepare slice of &Log
            let refs: Vec<&types::Log> = buffer.iter().map(|a| &**a).collect();

            let mut es_client = elastic_rx_for_indexer.borrow().clone();
            if es_client.is_none() {
                match timeout(Duration::from_secs(5), elastic_rx_for_indexer.changed()).await {
                    Ok(Ok(())) => {
                        es_client = elastic_rx_for_indexer.borrow().clone();
                    }
                    Ok(Err(_)) | Err(_) => {}
                }
            }

            if es_client.is_none() {
                error!("Elasticsearch unavailable, sending batch to DLQ until recovery");
                for a in &buffer {
                    if let Err(e) = kafka_for_indexer.send_log_to(LOGS_DLQ_TOPIC, &*a).await {
                        error!("failed to publish log to DLQ: {}", e);
                        metrics::counter!("siem_logs_index_dlq_errors_total", 1);
                    } else {
                        metrics::counter!("siem_logs_index_dlq_total", 1);
                    }
                }
                buffer.clear();
                sleep(Duration::from_millis(500)).await;
                continue;
            }

            let Some(es) = es_client else {
                continue;
            };

            // retry loop with exponential backoff
            let mut attempt = 0usize;
            let mut success = false;
            loop {
                match es.bulk_index(&idx, &refs).await {
                    Ok(_) => {
                        metrics::counter!("siem_logs_indexed_total", buffer.len() as u64);
                        let _ = redis_for_indexer.set_string("siem:health:indexer_last_seen", &Utc::now().timestamp().to_string(), Some(300)).await;
                        success = true;
                        break;
                    }
                    Err(e) => {
                        attempt += 1;
                        metrics::counter!("siem_logs_index_retries_total", 1);
                        error!("Elasticsearch bulk index attempt {} error: {}", attempt, e);
                        if attempt > max_retries {
                            break;
                        }
                        // backoff
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        backoff_ms = (backoff_ms * 2).min(10000);
                    }
                }
            }

                if !success {
                    // publish to DLQ topic to avoid silent loss
                    for a in &buffer {
                        if let Err(e) = kafka_for_indexer.send_log_to(LOGS_DLQ_TOPIC, &*a).await {
                            error!("failed to publish log to DLQ: {}", e);
                            metrics::counter!("siem_logs_index_dlq_errors_total", 1);
                        } else {
                            metrics::counter!("siem_logs_index_dlq_total", 1);
                        }
                    }
                }

            buffer.clear();
            // reset backoff for next batch
            backoff_ms = 500;

            if es_shutdown_rx.try_recv().is_ok() {
                info!("🛑 Elasticsearch indexer received shutdown, draining remaining queue");
                while let Ok(l) = index_rx.try_recv() {
                    buffer.push(l);
                    if buffer.len() >= batch_size {
                        let refs: Vec<&types::Log> = buffer.iter().map(|a| &**a).collect();
                        if let Ok(Some(es_client)) = timeout(Duration::from_secs(5), async { elastic_rx_for_indexer.borrow().clone() }).await {
                            if es_client.bulk_index(&idx, &refs).await.is_ok() {
                                let _ = redis_for_indexer.set_string("siem:health:indexer_last_seen", &Utc::now().timestamp().to_string(), Some(300)).await;
                            }
                        }
                        buffer.clear();
                    }
                }
                if !buffer.is_empty() {
                    let refs: Vec<&types::Log> = buffer.iter().map(|a| &**a).collect();
                    if let Ok(Some(es_client)) = timeout(Duration::from_secs(5), async { elastic_rx_for_indexer.borrow().clone() }).await {
                        if es_client.bulk_index(&idx, &refs).await.is_ok() {
                            let _ = redis_for_indexer.set_string("siem:health:indexer_last_seen", &Utc::now().timestamp().to_string(), Some(300)).await;
                        }
                    }
                }
                break;
            }
        }
    });
    task_registry.push("elasticsearch_indexer", es_handle);
    
    // Create shared application state for the API handlers.
    let app_state = web::Data::new(api::server::AppState {
        db: db.clone(),
        redis: redis.clone(),
        kafka: kafka.clone(),
        tenant_limits,
        audit_signing_key,
        elastic_index: elastic_index.clone(),
        ingest_tx: ingest_tx.clone(),
        log_tx: log_tx.clone(),
        alert_tx: alert_tx.clone(),
        stats_tx: stats_tx.clone(),
        elastic: elastic_rx.clone(),
    });

    let elastic_reconnect_tx = elastic_tx.clone();
    let elastic_reconnect_rx = elastic_rx.clone();
    let elastic_reconnect_host = elastic_host.clone();
    let elastic_reconnect_handle = task::spawn(async move {
        use tokio::time::{sleep, Duration};

        loop {
            sleep(Duration::from_secs(30)).await;

            if elastic_reconnect_rx.borrow().is_some() {
                continue;
            }

            match mini_siem::db::ElasticClient::new(&elastic_reconnect_host).await {
                Ok(c) => {
                    let client = Arc::new(c);
                    if elastic_reconnect_tx.send(Some(client)).is_ok() {
                        info!("✅ Elasticsearch reconnected, indexing re-enabled");
                    }
                }
                Err(e) => {
                    tracing::warn!("Elasticsearch still unavailable: {}", e);
                }
            }
        }
    });
    task_registry.push("elastic_reconnect", elastic_reconnect_handle);

    // Start dedicated alert worker to process alerts from Kafka asynchronously
    // Create DB batcher channel and spawn the DB batcher
    let (db_tx, db_rx) = mpsc::channel::<types::Alert>(1000);
    let db_batcher_handle = alerting::db_batcher::spawn_db_batcher(
        db.clone(),
        db_rx,
        shutdown_tx.subscribe(),
        100,
        1000,
    );
    task_registry.push("db_batcher", db_batcher_handle);

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
    task_registry.push("alert_worker", alert_worker_handle);

    // Start periodic Redis -> Postgres stats sync (reads Redis counters and persists them periodically)
    let db_clone_for_stats = db.clone();
    let redis_clone_for_stats = redis.clone();
    let stats_sync_handle = task::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            // best-effort: read counters from Redis
            let total_logs = redis_clone_for_stats.get_counter("siem:stats:total_logs").await.ok().flatten().map(|v| v as i64).unwrap_or(0);
            let total_alerts = redis_clone_for_stats.get_counter("siem:stats:total_alerts").await.ok().flatten().map(|v| v as i64).unwrap_or(0);
            let active_alerts = redis_clone_for_stats.get_counter("siem:stats:active_alerts").await.ok().flatten().map(|v| v as i64).unwrap_or(0);
            let critical_alerts = redis_clone_for_stats.get_counter("siem:stats:critical_alerts").await.ok().flatten().map(|v| v as i64).unwrap_or(0);

            if let Err(e) = db_clone_for_stats.save_stats("", total_logs, total_alerts, active_alerts, critical_alerts).await {
                error!("Failed to persist aggregated stats to DB: {}", e);
            }
        }
    });
    task_registry.push("stats_sync", stats_sync_handle);

    let db_clone_for_retention = db.clone();
    let elastic_rx_for_retention = elastic_rx.clone();
    let elastic_index_for_retention = elastic_index.clone();
    let mut retention_shutdown_rx = shutdown_tx.subscribe();
    let retention_handle = task::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    run_tenant_retention_cycle(&db_clone_for_retention, &elastic_rx_for_retention, &elastic_index_for_retention).await;
                }
                _ = retention_shutdown_rx.recv() => {
                    info!("🛑 Tenant retention worker received shutdown");
                    break;
                }
            }
        }
    });
    task_registry.push("tenant_retention", retention_handle);

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
        res = api::run_server(app_state.clone(), cfg.cors_allowed_origins.clone()) => {
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
    drop(app_state);
    drop(log_tx);
    drop(ingest_tx);
    drop(index_tx);
    drop(db_tx);
    let _ = shutdown_tx.send(());

    // Give background tasks a bounded chance to drain before falling back to abort.
    task_registry.drain(Duration::from_secs(15)).await;

    // Final checkpoint after drain so the latest counters are persisted even if
    // the periodic stats sync task was in flight during shutdown.
    final_stats_checkpoint(&db, &redis).await;

    observability.shutdown();

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

fn detection_partition_index(log: &types::Log, worker_count: usize, partition_key: &str) -> usize {
    if worker_count == 0 {
        return 0;
    }

    let mut hasher = FxHasher::default();
    match partition_key {
        "tenant" => {
            log.tenant_id.hash(&mut hasher);
        }
        "source_ip" => {
            log.source_ip.hash(&mut hasher);
        }
        "tenant_source_ip" | "tenant+source_ip" | "tenant_source" => {
            log.tenant_id.hash(&mut hasher);
            log.source_ip.hash(&mut hasher);
        }
        other => {
            log.tenant_id.hash(&mut hasher);
            log.source_ip.hash(&mut hasher);
            tracing::warn!("Unknown DETECTION_PARTITION_KEY '{}', falling back to tenant_source_ip", other);
        }
    }
    (hasher.finish() as usize) % worker_count
}