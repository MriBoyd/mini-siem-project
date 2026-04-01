// Kafka queue implementation using rdkafka (librdkafka binding).

use anyhow::Result;
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::message::{Header, Message, OwnedHeaders};
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::topic_partition_list::{Offset, TopicPartitionList};
use rdkafka::util::Timeout;
use serde_json;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use std::collections::{hash_map::DefaultHasher, HashMap};
use std::hash::{Hash, Hasher};
use crate::db::cache::Cache;
use crate::db::redis::RedisCache;
use metrics;

use crate::types::Log;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::mpsc::error::TrySendError;

const DEFAULT_TOPIC: &str = "siem-logs";
const ALERTS_TOPIC: &str = "siem-alerts";
pub const ALERTS_DLQ_TOPIC: &str = "siem-alerts-dlq";
pub const LOGS_DLQ_TOPIC: &str = "siem-logs-dlq";

#[derive(Clone, Debug)]
struct LocalRateLimitState {
    capacity: f64,
    tokens: f64,
    refill_per_ms: f64,
    last_refill_ms: i64,
    blocked_until_ms: i64,
    last_seen_ms: i64,
}

impl LocalRateLimitState {
    fn new(limit: u32, window_ms: u64, now_ms: i64) -> Self {
        let capacity = limit.max(1) as f64;
        let refill_per_ms = capacity / window_ms.max(1) as f64;

        Self {
            capacity,
            tokens: capacity,
            refill_per_ms,
            last_refill_ms: now_ms,
            blocked_until_ms: 0,
            last_seen_ms: now_ms,
        }
    }

    fn touch(&mut self, now_ms: i64) {
        self.last_seen_ms = now_ms;
    }

    fn refill(&mut self, now_ms: i64) {
        if now_ms <= self.last_refill_ms {
            return;
        }

        let elapsed_ms = (now_ms - self.last_refill_ms) as f64;
        self.tokens = (self.tokens + elapsed_ms * self.refill_per_ms).min(self.capacity);
        self.last_refill_ms = now_ms;
    }

    fn allow(&mut self, now_ms: i64) -> bool {
        self.touch(now_ms);

        if now_ms < self.blocked_until_ms {
            return false;
        }

        self.refill(now_ms);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn block_for(&mut self, now_ms: i64, window_ms: u64) {
        self.blocked_until_ms = now_ms + window_ms as i64;
        self.tokens = 0.0;
        self.touch(now_ms);
    }
}

pub struct KafkaQueue {
    producer: FutureProducer,
    consumer: Arc<StreamConsumer>,
    alert_consumer: Arc<StreamConsumer>,
    topic: String,
}

impl KafkaQueue {
    pub async fn new(brokers: &str) -> Result<Self> {
        // Try to create producer/consumer with retries and exponential backoff
        let mut attempt: u32 = 0;
        let max_attempts: u32 = 5;
        let mut backoff_ms: u64 = 500;

        loop {
            attempt += 1;
            let mut prod_cfg = ClientConfig::new();
            prod_cfg.set("bootstrap.servers", brokers);
            prod_cfg.set("message.timeout.ms", "5000");
            prod_cfg.set("reconnect.backoff.ms", "500");
            prod_cfg.set("reconnect.backoff.max.ms", "10000");

            match prod_cfg.create::<FutureProducer>() {
                Ok(producer) => {
                    let mut cons_cfg = ClientConfig::new();
                    cons_cfg.set("bootstrap.servers", brokers);
                    cons_cfg.set("group.id", "mini-siem-consumer");
                    cons_cfg.set("enable.partition.eof", "false");
                    cons_cfg.set("session.timeout.ms", "6000");
                    cons_cfg.set("enable.auto.commit", "true");
                    cons_cfg.set("reconnect.backoff.ms", "500");
                    cons_cfg.set("reconnect.backoff.max.ms", "10000");

                    match cons_cfg.create::<StreamConsumer>() {
                        Ok(consumer) => {
                            // Create a second consumer for alerts to avoid polling the
                            // same StreamConsumer from multiple tasks concurrently.
                            // First consumer will subscribe to logs only.
                            if let Err(e) = consumer.subscribe(&[DEFAULT_TOPIC]) {
                                tracing::warn!("failed to subscribe to topic {}: {}", DEFAULT_TOPIC, e);
                            }

                            // Create alert-specific consumer
                            match cons_cfg.create::<StreamConsumer>() {
                                Ok(alert_consumer) => {
                                    if let Err(e) = alert_consumer.subscribe(&[ALERTS_TOPIC]) {
                                        tracing::warn!("failed to subscribe alert consumer to {}: {}", ALERTS_TOPIC, e);
                                    }

                                    return Ok(KafkaQueue {
                                        producer,
                                        consumer: Arc::new(consumer),
                                        alert_consumer: Arc::new(alert_consumer),
                                        topic: DEFAULT_TOPIC.to_string(),
                                    });
                                }
                                Err(e) => {
                                    tracing::warn!("attempt {}: failed to create Kafka alert consumer: {}", attempt, e);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("attempt {}: failed to create Kafka consumer: {}", attempt, e);
                        }
                    }

                }
                Err(e) => {
                    tracing::warn!("attempt {}: failed to create Kafka producer: {}", attempt, e);
                }
            }

            if attempt >= max_attempts {
                return Err(anyhow::anyhow!("failed to connect to Kafka after {} attempts", max_attempts));
            }

            tracing::info!("will retry Kafka connection in {}ms", backoff_ms);
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            backoff_ms = (backoff_ms * 2).min(10000);
        }
    }

    pub async fn send_log(&self, log: &Log) -> Result<()> {
        let payload = serde_json::to_string(log)?;
        let headers = OwnedHeaders::new().insert(Header {
            key: "source_ip",
            value: Some(&log.source_ip),
        });

        let key = log.id.to_string();
        let record = FutureRecord::to(&self.topic)
            .payload(&payload)
            .key(&key)
            .headers(headers);

        match self.producer.send(record, Timeout::After(Duration::from_secs(5))).await {
            Ok((_partition, _offset)) => Ok(()),
            Err((e, _)) => Err(anyhow::anyhow!("Kafka send error: {:?}", e)),
        }
    }

    /// Send a log to a specific topic (used for DLQ publishing).
    pub async fn send_log_to(&self, topic: &str, log: &Log) -> Result<()> {
        let payload = serde_json::to_string(log)?;
        let headers = OwnedHeaders::new().insert(Header {
            key: "source_ip",
            value: Some(&log.source_ip),
        });

        let key = log.id.to_string();
        let record = FutureRecord::to(topic)
            .payload(&payload)
            .key(&key)
            .headers(headers);

        match self.producer.send(record, Timeout::After(Duration::from_secs(5))).await {
            Ok((_partition, _offset)) => Ok(()),
            Err((e, _)) => Err(anyhow::anyhow!("Kafka send error: {:?}", e)),
        }
    }

    pub async fn send_alert(&self, alert: &crate::types::Alert) -> Result<()> {
        let payload = serde_json::to_string(alert)?;

        let key = alert.id.to_string();
        let record = FutureRecord::to(ALERTS_TOPIC)
            .payload(&payload)
            .key(&key);

        match self.producer.send(record, Timeout::After(Duration::from_secs(5))).await {
            Ok((_partition, _offset)) => Ok(()),
            Err((e, _)) => Err(anyhow::anyhow!("Kafka send error: {:?}", e)),
        }
    }

    /// Send alert with retries and optional DLQ. `retries` is number of additional attempts
    /// after the first try. `backoff_ms` is initial backoff and will double on each retry.
    pub async fn send_alert_with_retry(&self, alert: &crate::types::Alert, retries: u32, backoff_ms: u64, dlq_topic: Option<&str>) -> Result<()> {
        let payload = serde_json::to_string(alert)?;
        let key = alert.id.to_string();

        let mut attempt: u32 = 0;
        let mut backoff = backoff_ms;

        loop {
            attempt += 1;
            let record = FutureRecord::to(ALERTS_TOPIC)
                .payload(&payload)
                .key(&key);

            match self.producer.send(record, Timeout::After(Duration::from_secs(5))).await {
                Ok((_p, _o)) => return Ok(()),
                Err((e, _)) => {
                    tracing::warn!("kafka send attempt {} failed: {:?}", attempt, e);
                    metrics::counter!("siem_kafka_send_retries_total", 1);
                    if attempt > retries {
                        // last resort: publish to DLQ topic if provided
                        if let Some(dt) = dlq_topic {
                            let dlq_record = FutureRecord::to(dt)
                                .payload(&payload)
                                .key(&key);
                            match self.producer.send(dlq_record, Timeout::After(Duration::from_secs(5))).await {
                                Ok((_p2, _o2)) => {
                                    tracing::info!("alert sent to DLQ topic {}", dt);
                                    metrics::counter!("siem_alerts_dlq_total", 1);
                                    return Ok(());
                                }
                                Err((e2, _)) => {
                                    return Err(anyhow::anyhow!("Kafka send failed and DLQ publish failed: {:?}; original: {:?}", e2, e));
                                }
                            }
                        }

                        return Err(anyhow::anyhow!("Kafka send failed after {} attempts: {:?}", attempt, e));
                    }
                }
            }

            // backoff before retry
            tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
            backoff = (backoff * 2).min(10000);
        }
    }

    pub fn spawn_partition_lag_metrics_task(&self, sample_interval_secs: u64, watermark_timeout_ms: u64) -> tokio::task::JoinHandle<()> {
        let consumer = self.consumer.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(sample_interval_secs.max(1)));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                interval.tick().await;

                let assignment: TopicPartitionList = match consumer.assignment() {
                    Ok(assignment) => assignment,
                    Err(e) => {
                        tracing::warn!("failed to read Kafka assignment for lag metrics: {}", e);
                        continue;
                    }
                };

                for partition in assignment.elements() {
                    let topic = partition.topic().to_string();
                    let partition_id = partition.partition();
                    let current_offset = match partition.offset() {
                        Offset::Offset(offset) => Some(offset),
                        _ => None,
                    };

                    match consumer.fetch_watermarks(&topic, partition_id, Timeout::After(Duration::from_millis(watermark_timeout_ms.max(1)))) {
                        Ok((_low, high)) => {
                            metrics::gauge!("siem_kafka_partition_highwater_offset", high as f64, "topic" => topic.clone(), "partition" => partition_id.to_string());
                            if let Some(current) = current_offset {
                                metrics::gauge!("siem_kafka_partition_consumer_offset", current as f64, "topic" => topic.clone(), "partition" => partition_id.to_string());
                                let lag = if high >= current { (high - current) as f64 } else { 0.0 };
                                metrics::gauge!("siem_kafka_partition_lag", lag, "topic" => topic.clone(), "partition" => partition_id.to_string());
                            }
                        }
                        Err(e) => {
                            tracing::warn!("failed to fetch Kafka watermarks for lag metrics: {}", e);
                        }
                    }
                }
            }
        })
    }

    pub async fn health(&self) -> Result<()> {
        let _ = self.consumer.fetch_metadata(None, Timeout::After(Duration::from_secs(2)))?;
        let _ = self.alert_consumer.fetch_metadata(None, Timeout::After(Duration::from_secs(2)))?;
        Ok(())
    }

    /// Consume from Kafka and forward logs into the provided `tx`.
    /// `full_counter` is incremented when the channel is full (monitoring aid).
    pub async fn consume_logs(&self, tx: mpsc::Sender<std::sync::Arc<Log>>, index_tx: Option<mpsc::Sender<std::sync::Arc<Log>>>, full_counter: Option<Arc<AtomicUsize>>, pause_on_full: bool, pause_timeout_ms: u64, rate_limit_per_ip: usize, rate_limit_window_ms: u64, rate_limit_sample_rate: u32, redis: RedisCache) -> Result<()> {
        let mut stream = self.consumer.stream();
        let mut local_rate_limits: HashMap<String, LocalRateLimitState> = HashMap::new();
        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(30));
        cleanup_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = cleanup_interval.tick() => {
                    let now_ms = chrono::Utc::now().timestamp_millis();
                    let expiry_ms = (rate_limit_window_ms as i64).saturating_mul(4).max(60_000);
                    local_rate_limits.retain(|_, state| now_ms.saturating_sub(state.last_seen_ms) <= expiry_ms);
                }
                message = stream.next() => match message {
                Some(Ok(msg)) => {
                    if let Some(payload) = msg.payload() {
                        if let Ok(log) = serde_json::from_slice::<Log>(payload) {
                            // Centralized Redis sliding-window rate limiter per IP
                            let source_ip = log.source_ip.clone();
                            let now_ms = chrono::Utc::now().timestamp_millis();
                            let rl_key = format!("siem:ratelimit:ip:{}", source_ip);
                            let state = local_rate_limits.entry(source_ip.clone()).or_insert_with(|| LocalRateLimitState::new(rate_limit_per_ip as u32, rate_limit_window_ms, now_ms));

                            let allowed = if state.allow(now_ms) {
                                true
                            } else {
                                match redis.allow_sliding_window(&rl_key, rate_limit_window_ms, rate_limit_per_ip as u32).await {
                                    Ok(true) => {
                                        state.tokens = 0.0;
                                        true
                                    }
                                    Ok(false) => {
                                        state.block_for(now_ms, rate_limit_window_ms);
                                        let mut hasher = DefaultHasher::new();
                                        log.id.hash(&mut hasher);
                                        let h = hasher.finish();
                                        let sample = if rate_limit_sample_rate <= 1 { true } else { (h % (rate_limit_sample_rate as u64)) == 0 };
                                        if sample {
                                            metrics::counter!("siem_logs_sampled_total", 1, "source_ip" => source_ip.clone());
                                        } else {
                                            metrics::counter!("siem_logs_rate_limited_total", 1, "source_ip" => source_ip.clone());
                                        }
                                        sample
                                    }
                                    Err(e) => {
                                        tracing::warn!("redis rate limiter error: {} - allowing log to avoid data loss", e);
                                        true
                                    }
                                }
                            };

                            if !allowed {
                                continue;
                            }

                            let _ = redis.set_string("siem:health:kafka_last_seen", &chrono::Utc::now().timestamp().to_string(), Some(300)).await;

                            let arc_log = std::sync::Arc::new(log);

                            // Try sending to primary pipeline (detection)
                            match tx.try_send(arc_log.clone()) {
                                Ok(_) => {
                                    if let Some(cnt) = full_counter.as_ref() {
                                        cnt.store(0, Ordering::Relaxed);
                                    }
                                }
                                Err(TrySendError::Full(l)) => {
                                    if pause_on_full {
                                        if let Ok(assignment) = self.consumer.assignment() {
                                            if let Err(e) = self.consumer.pause(&assignment) {
                                                tracing::warn!("failed to pause consumer: {}", e);
                                            }

                                            if pause_timeout_ms == 0 {
                                                if tx.send(l).await.is_ok() {
                                                    let _ = self.consumer.resume(&assignment);
                                                    if let Some(cnt) = full_counter.as_ref() { cnt.store(0, Ordering::Relaxed); }
                                                } else {
                                                    tracing::warn!("log channel closed while sending, stopping consumer");
                                                    break;
                                                }
                                            } else {
                                                use tokio::time::{timeout, Duration};
                                                match timeout(Duration::from_millis(pause_timeout_ms), tx.send(l)).await {
                                                    Ok(Ok(())) => { let _ = self.consumer.resume(&assignment); if let Some(cnt) = full_counter.as_ref() { cnt.store(0, Ordering::Relaxed); } }
                                                    Ok(Err(_)) => { tracing::warn!("log channel closed while sending, stopping consumer"); break; }
                                                    Err(_) => { let _ = self.consumer.resume(&assignment); if let Some(cnt) = full_counter.as_ref() { cnt.fetch_add(1, Ordering::Relaxed); } tracing::warn!("log channel full after pause timeout, dropping message"); }
                                                }
                                            }
                                        } else {
                                            use tokio::time::{timeout, Duration};
                                            let wait_ms = if pause_timeout_ms == 0 { 50 } else { std::cmp::min(50, pause_timeout_ms) };
                                            match timeout(Duration::from_millis(wait_ms), tx.send(l)).await {
                                                Ok(Ok(())) => { if let Some(cnt) = full_counter.as_ref() { cnt.store(0, Ordering::Relaxed); } }
                                                Ok(Err(_)) => { tracing::warn!("log channel closed while sending, stopping consumer"); break; }
                                                Err(_) => { if let Some(cnt) = full_counter.as_ref() { cnt.fetch_add(1, Ordering::Relaxed); } tracing::warn!("log channel full after wait, dropping message"); }
                                            }
                                        }
                                    } else {
                                        use tokio::time::{timeout, Duration};
                                        match timeout(Duration::from_millis(50), tx.send(l)).await {
                                            Ok(Ok(())) => { if let Some(cnt) = full_counter.as_ref() { cnt.store(0, Ordering::Relaxed); } }
                                            Ok(Err(_)) => { tracing::warn!("log channel closed while sending, stopping consumer"); break; }
                                            Err(_) => { if let Some(cnt) = full_counter.as_ref() { cnt.fetch_add(1, Ordering::Relaxed); } tracing::warn!("log channel full after wait, dropping message"); }
                                        }
                                    }
                                }
                                Err(TrySendError::Closed(_)) => { tracing::warn!("log channel closed, stopping consumer"); break; }
                            }

                            // best-effort forward to indexer
                            if let Some(idx) = index_tx.as_ref() {
                                match idx.try_send(arc_log.clone()) {
                                    Ok(_) => {}
                                    Err(TrySendError::Full(_)) => { metrics::counter!("siem_logs_indexer_full", 1); }
                                    Err(TrySendError::Closed(_)) => { tracing::warn!("indexer channel closed"); }
                                }
                            }
                        }
                    }
                }
                Some(Err(e)) => { tracing::warn!("kafka consumer error: {}", e); }
                None => break,
                },
            }
        }
        Ok(())
    }

    /// Consume alerts from Kafka and forward into the provided `tx` for processing.
    pub async fn consume_alerts(&self, tx: mpsc::Sender<crate::types::Alert>, full_counter: Option<Arc<AtomicUsize>>, pause_on_full: bool, pause_timeout_ms: u64, redis: RedisCache) -> Result<()> {
        let mut stream = self.alert_consumer.stream();

        while let Some(message) = stream.next().await {
            match message {
                Ok(msg) => {
                    if let Some(Ok(payload)) = msg.payload_view::<str>() {
                        if let Ok(alert) = serde_json::from_str::<crate::types::Alert>(payload) {
                            let _ = redis.set_string("siem:health:kafka_last_seen", &chrono::Utc::now().timestamp().to_string(), Some(300)).await;
                            match tx.try_send(alert) {
                                Ok(_) => {
                                    if let Some(cnt) = full_counter.as_ref() {
                                        cnt.store(0, Ordering::Relaxed);
                                    }
                                }
                                Err(TrySendError::Full(a)) => {
                                    if pause_on_full {
                                        match self.consumer.assignment() {
                                            Ok(assignment) => {
                                                if let Err(e) = self.consumer.pause(&assignment) {
                                                    tracing::warn!("failed to pause consumer: {}", e);
                                                }

                                                if pause_timeout_ms == 0 {
                                                    match tx.send(a).await {
                                                        Ok(()) => {
                                                            if let Err(e) = self.consumer.resume(&assignment) {
                                                                tracing::warn!("failed to resume consumer: {}", e);
                                                            }
                                                            if let Some(cnt) = full_counter.as_ref() {
                                                                cnt.store(0, Ordering::Relaxed);
                                                            }
                                                        }
                                                        Err(_) => {
                                                            tracing::warn!("alert channel closed while sending, stopping consumer");
                                                            break;
                                                        }
                                                    }
                                                } else {
                                                    use tokio::time::{timeout, Duration};
                                                    match timeout(Duration::from_millis(pause_timeout_ms), tx.send(a)).await {
                                                        Ok(Ok(())) => {
                                                            if let Err(e) = self.consumer.resume(&assignment) {
                                                                tracing::warn!("failed to resume consumer: {}", e);
                                                            }
                                                            if let Some(cnt) = full_counter.as_ref() {
                                                                cnt.store(0, Ordering::Relaxed);
                                                            }
                                                        }
                                                        Ok(Err(_)) => {
                                                            tracing::warn!("alert channel closed while sending, stopping consumer");
                                                            break;
                                                        }
                                                        Err(_) => {
                                                            if let Err(e) = self.consumer.resume(&assignment) {
                                                                tracing::warn!("failed to resume consumer: {}", e);
                                                            }
                                                            if let Some(cnt) = full_counter.as_ref() {
                                                                cnt.fetch_add(1, Ordering::Relaxed);
                                                            }
                                                            tracing::warn!("alert channel full after pause timeout, dropping message");
                                                        }
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                tracing::warn!("couldn't get consumer assignment: {}", e);
                                                use tokio::time::{timeout, Duration};
                                                let wait_ms = if pause_timeout_ms == 0 { 50 } else { std::cmp::min(50, pause_timeout_ms) };
                                                match timeout(Duration::from_millis(wait_ms), tx.send(a)).await {
                                                    Ok(Ok(())) => {
                                                        if let Some(cnt) = full_counter.as_ref() {
                                                            cnt.store(0, Ordering::Relaxed);
                                                        }
                                                    }
                                                    Ok(Err(_)) => {
                                                        tracing::warn!("alert channel closed while sending, stopping consumer");
                                                        break;
                                                    }
                                                    Err(_) => {
                                                        if let Some(cnt) = full_counter.as_ref() {
                                                            cnt.fetch_add(1, Ordering::Relaxed);
                                                        }
                                                        tracing::warn!("alert channel full after wait, dropping message");
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        use tokio::time::{timeout, Duration};
                                        let wait_ms = if pause_timeout_ms == 0 { 50 } else { std::cmp::min(50, pause_timeout_ms) };
                                        match timeout(Duration::from_millis(wait_ms), tx.send(a)).await {
                                            Ok(Ok(())) => {
                                                if let Some(cnt) = full_counter.as_ref() {
                                                    cnt.store(0, Ordering::Relaxed);
                                                }
                                            }
                                            Ok(Err(_)) => {
                                                tracing::warn!("alert channel closed while sending, stopping consumer");
                                                break;
                                            }
                                            Err(_) => {
                                                if let Some(cnt) = full_counter.as_ref() {
                                                    cnt.fetch_add(1, Ordering::Relaxed);
                                                }
                                                tracing::warn!("alert channel full after wait, dropping message");
                                            }
                                        }
                                    }
                                }
                                Err(TrySendError::Closed(_)) => {
                                    tracing::warn!("alert channel closed, stopping consumer");
                                    break;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("kafka consumer error: {}", e);
                }
            }
        }

        Ok(())
    }
}

