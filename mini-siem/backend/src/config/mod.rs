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

        Ok(Self {
            database_url,
            redis_url,
            kafka_brokers,
            slack_webhook,
            api_bind,
            metrics_bind,
        })
    }
}
