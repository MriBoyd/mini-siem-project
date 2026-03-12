// Slack notifier

pub struct SlackNotifier {
    webhook_url: Option<String>,
}

impl SlackNotifier {
    pub fn new(webhook_url: Option<String>) -> Self {
        SlackNotifier { webhook_url }
    }

    pub async fn send_alert(&self, alert: &crate::types::Alert) -> anyhow::Result<()> {
        if let Some(url) = &self.webhook_url {
            // placeholder: in real code we'd post to Slack
            println!("Slack webhook {} would receive alert {}", url, alert.description);
        }
        Ok(())
    }
}
