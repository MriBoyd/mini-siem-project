use anyhow::Context;
use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub redis_url: String,
    pub kafka_brokers: String,
    pub slack_webhook: Option<String>,
    pub api_bind: String,
    pub metrics_bind: String,
    pub kafka_pause_on_full: bool,
    pub kafka_pause_timeout_ms: u64,
    pub rate_limit_per_ip: usize,
    pub rate_limit_window_ms: u64,
    pub rate_limit_sample_rate: u32,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        dotenvy::dotenv().ok();

        let database_url = env::var("DATABASE_URL").context("DATABASE_URL must be set")?;
        let redis_url = env::var("REDIS_URL").context("REDIS_URL must be set")?;
        let kafka_brokers = env::var("KAFKA_BROKERS").unwrap_or_else(|_| "localhost:9092".to_string());
        let slack_webhook = env::var("SLACK_WEBHOOK").ok();
        let api_bind = env::var("API_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
        let metrics_bind = env::var("METRICS_BIND").unwrap_or_else(|_| "127.0.0.1:9898".to_string());
        let kafka_pause_on_full = env::var("KAFKA_PAUSE_ON_FULL").ok()
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(true);
        let kafka_pause_timeout_ms = env::var("KAFKA_PAUSE_TIMEOUT_MS").ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5000);
        let rate_limit_per_ip = env::var("RATE_LIMIT_PER_IP").ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);
        let rate_limit_window_ms = env::var("RATE_LIMIT_WINDOW_MS").ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1000);
        let rate_limit_sample_rate = env::var("RATE_LIMIT_SAMPLE_RATE").ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);

        Ok(Self {
            database_url,
            redis_url,
            kafka_brokers,
            slack_webhook,
            api_bind,
            metrics_bind,
            kafka_pause_on_full,
            kafka_pause_timeout_ms,
            rate_limit_per_ip,
            rate_limit_window_ms,
            rate_limit_sample_rate,
        })
    }
}
