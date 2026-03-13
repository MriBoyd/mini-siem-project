// Kafka consumer/producer (in-memory placeholder implementation)

use anyhow::Result;
use tokio::sync::mpsc;
use std::sync::Arc;

use crate::types::Log;

/// Simple placeholder for a Kafka queue client.
///
/// In this prototype, the "Kafka" queue is implemented as an in-memory channel.
/// This allows the code to be structured around a queue interface while being
/// runnable without a real Kafka cluster.
#[derive(Clone)]
pub struct KafkaQueue {
    brokers: String,
    tx: mpsc::Sender<Log>,
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Log>>>,
}

impl KafkaQueue {
    pub async fn new(brokers: &str) -> Result<Self> {
        // In real implementation, connect to Kafka cluster here.
        // For now we use an internal channel as the queue.
        let (tx, rx) = mpsc::channel::<Log>(10_000);
        Ok(KafkaQueue {
            brokers: brokers.to_string(),
            tx,
            rx: Arc::new(tokio::sync::Mutex::new(rx)),
        })
    }

    /// Send a log into the queue.
    pub async fn send_log(&self, log: &Log) -> Result<()> {
        self.tx
            .send(log.clone())
            .await
            .map_err(|e| anyhow::anyhow!("failed to enqueue log: {}", e))
    }

    /// Consume logs from the queue and forward them into `tx`.
    ///
    /// This is what the consumer loop would do in a real Kafka client.
    pub async fn consume_logs(&self, tx: mpsc::Sender<Log>) -> Result<()> {
        let mut rx = self.rx.lock().await;
        while let Some(log) = rx.recv().await {
            if tx.send(log).await.is_err() {
                // downstream receiver is closed; stop consuming
                break;
            }
        }
        Ok(())
    }
}

