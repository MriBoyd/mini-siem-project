use reqwest::Client;
use serde_json::json;
use tracing::{info, error};
use anyhow::Result;

use crate::types::Alert;

pub struct SlackNotifier {
    webhook_url: String,
    client: Client,
    enabled: bool,
}

impl SlackNotifier {
    pub fn new(webhook_url: Option<String>) -> Self {
        let enabled = webhook_url.is_some();
        
        Self {
            webhook_url: webhook_url.unwrap_or_default(),
            client: Client::new(),
            enabled,
        }
    }
    
    pub async fn send_alert(&self, alert: &Alert) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        
        // Choose color based on severity
        let color = match alert.severity {
            crate::types::AlertSeverity::Critical => "danger",
            crate::types::AlertSeverity::High => "warning",
            crate::types::AlertSeverity::Medium => "warning",
            crate::types::AlertSeverity::Low => "good",
            crate::types::AlertSeverity::Info => "#808080",
        };
        
        // Create Slack message
        let payload = json!({
            "attachments": [{
                "color": color,
                "title": format!("🚨 {}: {}", alert.severity, alert.rule_name),
                "text": alert.description,
                "fields": [
                    {
                        "title": "Source IP",
                        "value": alert.source_ip,
                        "short": true
                    },
                    {
                        "title": "Events Count",
                        "value": alert.events_count.to_string(),
                        "short": true
                    },
                    {
                        "title": "First Seen",
                        "value": alert.first_seen.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                        "short": true
                    },
                    {
                        "title": "Last Seen",
                        "value": alert.last_seen.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                        "short": true
                    }
                ],
                "footer": "Mini SIEM",
                "ts": alert.last_seen.timestamp()
            }]
        });
        
        let response = self.client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await?;
        
        if response.status().is_success() {
            info!("📢 Slack notification sent for alert {}", alert.id);
        } else {
            error!("Failed to send Slack notification: {}", response.status());
        }
        
        Ok(())
    }
}