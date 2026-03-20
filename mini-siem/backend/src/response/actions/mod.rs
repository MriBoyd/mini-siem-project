use async_trait::async_trait;
use crate::types::Alert;
use anyhow::Result;
use std::fmt::Debug;
use reqwest::Client;
use tracing::{info, error};

#[async_trait]
pub trait ResponseAction: Send + Sync + Debug {
    fn name(&self) -> &str;
    async fn execute(&self, alert: &Alert) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct WebhookAction {
    pub name: String,
    pub url: String,
    client: Client,
}

impl WebhookAction {
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            client: Client::new(),
        }
    }
}

#[async_trait]
impl ResponseAction for WebhookAction {
    fn name(&self) -> &str {
        &self.name
    }

    async fn execute(&self, alert: &Alert) -> Result<()> {
        info!("Executing WebhookAction '{}' for Alert {}", self.name, alert.id);
        
        let response = self.client.post(&self.url)
            .json(alert)
            .send()
            .await?;
            
        if !response.status().is_success() {
            error!("WebhookAction '{}' failed with status: {}", self.name, response.status());
            anyhow::bail!("Webhook failed with status: {}", response.status());
        }

        info!("WebhookAction '{}' executed successfully", self.name);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ScriptAction {
    pub name: String,
    pub script_path: String,
    pub args: Vec<String>,
}

impl ScriptAction {
    pub fn new(name: impl Into<String>, script_path: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            name: name.into(),
            script_path: script_path.into(),
            args,
        }
    }
}

#[async_trait]
impl ResponseAction for ScriptAction {
    fn name(&self) -> &str {
        &self.name
    }

    async fn execute(&self, alert: &Alert) -> Result<()> {
        info!("Executing ScriptAction '{}' for Alert {}", self.name, alert.id);
        
        // Pass alert fields as environment variables or arguments? Let's use env vars for safety + flexibility.
        let status = tokio::process::Command::new(&self.script_path)
            .args(&self.args)
            .env("ALERT_ID", alert.id.to_string())
            .env("ALERT_SEVERITY", alert.severity.to_string())
            .env("ALERT_SOURCE_IP", &alert.source_ip)
            .env("ALERT_DESCRIPTION", &alert.description)
            .status()
            .await?;

        if !status.success() {
            error!("ScriptAction '{}' failed with status: {}", self.name, status);
            anyhow::bail!("Script failed with status: {}", status);
        }

        info!("ScriptAction '{}' executed successfully", self.name);
        Ok(())
    }
}
