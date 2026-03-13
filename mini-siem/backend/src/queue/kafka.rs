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

use crate::types::Log;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::mpsc::error::TrySendError;

const DEFAULT_TOPIC: &str = "siem-logs";

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

    /// Consume from Kafka and forward logs into the provided `tx`.
    /// `full_counter` is incremented when the channel is full (monitoring aid).
    pub async fn consume_logs(&self, tx: mpsc::Sender<Log>, full_counter: Option<Arc<AtomicUsize>>) -> Result<()> {
        let mut stream = self.consumer.stream();

        while let Some(message) = stream.next().await {
            match message {
                Ok(msg) => {
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
                                Err(TrySendError::Full(_)) => {
                                    if let Some(cnt) = full_counter.as_ref() {
                                        cnt.fetch_add(1, Ordering::Relaxed);
                                    }
                                    tracing::warn!("log channel full, dropping message");
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
}

