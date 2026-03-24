// Alert manager

use anyhow::Result;
use std::sync::Arc;

use crate::types::Alert;
use crate::alerting::notifiers::slack::SlackNotifier;

/// Handle an alert: persist to Postgres, notify Slack (if configured), and trigger
/// the response engine. This is a small convenience wrapper used by the
/// detection pipeline when immediate processing is required.
pub async fn handle_alert(
    db: Arc<crate::db::PostgresDb>,
    response_engine: Arc<crate::response::engine::ResponseEngine>,
    alert: &Alert,
) -> Result<()> {
    // Persist alert to Postgres (best-effort; return error to caller if it fails)
    db.create_alert(alert).await.map_err(|e| anyhow::anyhow!(e))?;

    // Send Slack notification if configured via environment
    let webhook = std::env::var("SLACK_WEBHOOK").ok();
    let slack = SlackNotifier::new(webhook);
    if let Err(e) = slack.send_alert(alert).await {
        tracing::error!("failed to send slack notification: {}", e);
    }

    // Trigger response engine (e.g., run automated responses)
    response_engine.handle_alert(alert).await;

    Ok(())
}
