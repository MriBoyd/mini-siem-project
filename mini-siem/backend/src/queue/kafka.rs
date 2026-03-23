// Kafka queue implementation using rdkafka (librdkafka binding).

use anyhow::Result;
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::message::{Header, Message, OwnedHeaders};
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::util::Timeout;
use serde_json;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use metrics;

use crate::types::Log;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::mpsc::error::TrySendError;

const DEFAULT_TOPIC: &str = "siem-logs";
const ALERTS_TOPIC: &str = "siem-alerts";
pub const ALERTS_DLQ_TOPIC: &str = "siem-alerts-dlq";

pub struct KafkaQueue {
    producer: FutureProducer,
    consumer: StreamConsumer,
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
                            if let Err(e) = consumer.subscribe(&[DEFAULT_TOPIC]) {
                                tracing::warn!("failed to subscribe to topic {}: {}", DEFAULT_TOPIC, e);
                            }

                            return Ok(KafkaQueue {
                                producer,
                                consumer,
                                topic: DEFAULT_TOPIC.to_string(),
                            });
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
                    if attempt > retries {
                        // last resort: publish to DLQ topic if provided
                        if let Some(dt) = dlq_topic {
                            let dlq_record = FutureRecord::to(dt)
                                .payload(&payload)
                                .key(&key);
                            match self.producer.send(dlq_record, Timeout::After(Duration::from_secs(5))).await {
                                Ok((_p2, _o2)) => {
                                    tracing::info!("alert sent to DLQ topic {}", dt);
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

    /// Consume from Kafka and forward logs into the provided `tx`.
    /// `full_counter` is incremented when the channel is full (monitoring aid).
    pub async fn consume_logs(&self, tx: mpsc::Sender<Log>, full_counter: Option<Arc<AtomicUsize>>, pause_on_full: bool, pause_timeout_ms: u64) -> Result<()> {
        let mut stream = self.consumer.stream();

        while let Some(message) = stream.next().await {
            match message {
                Ok(msg) => {
                    // Observe consumer offset and partition highwater (if available).
                    let topic = msg.topic().to_string();
                    let partition = msg.partition();
                    let offset = msg.offset();
                    metrics::gauge!("siem_kafka_partition_consumer_offset", offset as f64, "topic" => topic.clone(), "partition" => partition.to_string());
                    // try to fetch highwater mark for this partition
                    match self.consumer.fetch_watermarks(&topic, partition, Timeout::After(Duration::from_millis(500))) {
                        Ok((_low, high)) => {
                            metrics::gauge!("siem_kafka_partition_highwater_offset", high as f64, "topic" => topic.clone(), "partition" => partition.to_string());
                            // kafka lag can be derived as high - offset
                            let lag = if high >= offset { (high - offset) as f64 } else { 0.0 };
                            metrics::gauge!("siem_kafka_partition_lag", lag, "topic" => topic.clone(), "partition" => partition.to_string());
                        }
                        Err(_) => {}
                    }
                    if let Some(Ok(payload)) = msg.payload_view::<str>() {
                        if let Ok(log) = serde_json::from_str::<Log>(payload) {
                            // Use try_send to avoid blocking the kafka stream when the
                            // downstream channel is full. If full, increment counter and drop.
                            match tx.try_send(log) {
                                Ok(_) => {
                                    if let Some(cnt) = full_counter.as_ref() {
                                        cnt.store(0, Ordering::Relaxed);
                                    }
                                }
                                Err(TrySendError::Full(l)) => {
                                    if pause_on_full {
                                        // Try to pause consumer and block until there's space.
                                        match self.consumer.assignment() {
                                            Ok(assignment) => {
                                                if let Err(e) = self.consumer.pause(&assignment) {
                                                    tracing::warn!("failed to pause consumer: {}", e);
                                                }
                                                // Use timeout controlled by caller; 0 means wait indefinitely
                                                if pause_timeout_ms == 0 {
                                                    match tx.send(l).await {
                                                        Ok(()) => {
                                                            if let Err(e) = self.consumer.resume(&assignment) {
                                                                tracing::warn!("failed to resume consumer: {}", e);
                                                            }
                                                            if let Some(cnt) = full_counter.as_ref() {
                                                                cnt.store(0, Ordering::Relaxed);
                                                            }
                                                        }
                                                        Err(_) => {
                                                            tracing::warn!("log channel closed while sending, stopping consumer");
                                                            break;
                                                        }
                                                    }
                                                } else {
                                                    use tokio::time::{timeout, Duration};
                                                    match timeout(Duration::from_millis(pause_timeout_ms), tx.send(l)).await {
                                                        Ok(Ok(())) => {
                                                            if let Err(e) = self.consumer.resume(&assignment) {
                                                                tracing::warn!("failed to resume consumer: {}", e);
                                                            }
                                                            if let Some(cnt) = full_counter.as_ref() {
                                                                cnt.store(0, Ordering::Relaxed);
                                                            }
                                                        }
                                                        Ok(Err(_)) => {
                                                            tracing::warn!("log channel closed while sending, stopping consumer");
                                                            break;
                                                        }
                                                        Err(_) => {
                                                            // timed out
                                                            if let Err(e) = self.consumer.resume(&assignment) {
                                                                tracing::warn!("failed to resume consumer: {}", e);
                                                            }
                                                            if let Some(cnt) = full_counter.as_ref() {
                                                                cnt.fetch_add(1, Ordering::Relaxed);
                                                            }
                                                            tracing::warn!("log channel full after pause timeout, dropping message");
                                                        }
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                tracing::warn!("couldn't get consumer assignment: {}", e);
                                                // fallback to short wait
                                                use tokio::time::{timeout, Duration};
                                                let wait_ms = if pause_timeout_ms == 0 { 50 } else { std::cmp::min(50, pause_timeout_ms) };
                                                match timeout(Duration::from_millis(wait_ms), tx.send(l)).await {
                                                    Ok(Ok(())) => {
                                                        if let Some(cnt) = full_counter.as_ref() {
                                                            cnt.store(0, Ordering::Relaxed);
                                                        }
                                                    }
                                                    Ok(Err(_)) => {
                                                        tracing::warn!("log channel closed while sending, stopping consumer");
                                                        break;
                                                    }
                                                    Err(_) => {
                                                        if let Some(cnt) = full_counter.as_ref() {
                                                            cnt.fetch_add(1, Ordering::Relaxed);
                                                        }
                                                        tracing::warn!("log channel full after wait, dropping message");
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        // fallback: short wait then drop
                                        use tokio::time::{timeout, Duration};
                                        match timeout(Duration::from_millis(50), tx.send(l)).await {
                                            Ok(Ok(())) => {
                                                if let Some(cnt) = full_counter.as_ref() {
                                                    cnt.store(0, Ordering::Relaxed);
                                                }
                                            }
                                            Ok(Err(_)) => {
                                                tracing::warn!("log channel closed while sending, stopping consumer");
                                                break;
                                            }
                                            Err(_) => {
                                                if let Some(cnt) = full_counter.as_ref() {
                                                    cnt.fetch_add(1, Ordering::Relaxed);
                                                }
                                                tracing::warn!("log channel full after wait, dropping message");
                                            }
                                        }
                                    }
                                }
                                Err(TrySendError::Closed(_)) => {
                                    tracing::warn!("log channel closed, stopping consumer");
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

    /// Consume alerts from Kafka and forward into the provided `tx` for processing.
    pub async fn consume_alerts(&self, tx: mpsc::Sender<crate::types::Alert>, full_counter: Option<Arc<AtomicUsize>>, pause_on_full: bool, pause_timeout_ms: u64) -> Result<()> {
        let mut stream = self.consumer.stream();

        while let Some(message) = stream.next().await {
            match message {
                Ok(msg) => {
                    if let Some(Ok(payload)) = msg.payload_view::<str>() {
                        if let Ok(alert) = serde_json::from_str::<crate::types::Alert>(payload) {
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

