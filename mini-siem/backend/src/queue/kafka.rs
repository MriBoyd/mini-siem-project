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

const DEFAULT_TOPIC: &str = "siem-logs";

pub struct KafkaQueue {
    producer: FutureProducer,
    consumer: StreamConsumer,
    topic: String,
}

impl KafkaQueue {
    pub async fn new(brokers: &str) -> Result<Self> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("message.timeout.ms", "5000")
            .create()?;

        let consumer: StreamConsumer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("group.id", "mini-siem-consumer")
            .set("enable.partition.eof", "false")
            .set("session.timeout.ms", "6000")
            .set("enable.auto.commit", "true")
            .create()?;

        consumer.subscribe(&[DEFAULT_TOPIC])?;

        Ok(KafkaQueue {
            producer,
            consumer,
            topic: DEFAULT_TOPIC.to_string(),
        })
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

        match self.producer.send(record, Timeout::Never).await {
            Ok((_partition, _offset)) => Ok(()),
            Err((e, _)) => Err(anyhow::anyhow!("Kafka send error: {:?}", e)),
        }
    }

    pub async fn consume_logs(&self, tx: mpsc::Sender<Log>) -> Result<()> {
        let mut stream = self.consumer.stream();

        while let Some(message) = stream.next().await {
            match message {
                Ok(msg) => {
                    if let Some(Ok(payload)) = msg.payload_view::<str>() {
                        if let Ok(log) = serde_json::from_str::<Log>(payload) {
                            let _ = tx.send(log).await;
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

