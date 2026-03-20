use std::sync::Arc;
use tokio::sync::Mutex;
use async_trait::async_trait;
use mini_siem::types::{Alert, AlertSeverity};
use mini_siem::response::engine::ResponseEngine;
use mini_siem::response::actions::ResponseAction;
use anyhow::Result;

#[derive(Debug)]
struct MockAction {
    pub name: String,
    pub call_count: Arc<Mutex<u32>>,
}

#[async_trait]
impl ResponseAction for MockAction {
    fn name(&self) -> &str {
        &self.name
    }

    async fn execute(&self, _alert: &Alert) -> Result<()> {
        let mut count = self.call_count.lock().await;
        *count += 1;
        Ok(())
    }
}

#[tokio::test]
async fn test_response_engine_triggers_on_severity() {
    let engine = ResponseEngine::new();
    let call_count = Arc::new(Mutex::new(0));
    let action = Arc::new(MockAction {
        name: "test_action".to_string(),
        call_count: call_count.clone(),
    });

    engine.add_severity_policy(AlertSeverity::Critical, action).await;

    let alert = Alert::new(
        "rule_1",
        "Test Rule",
        AlertSeverity::Critical,
        "Test description",
        "1.1.1.1",
        vec![]
    );

    engine.handle_alert(&alert).await;

    // Wait a short bit since it's spawned in a background task
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let final_count = *call_count.lock().await;
    assert_eq!(final_count, 1);
}

#[tokio::test]
async fn test_response_engine_triggers_on_rule_id() {
    let engine = ResponseEngine::new();
    let call_count = Arc::new(Mutex::new(0));
    let action = Arc::new(MockAction {
        name: "test_action".to_string(),
        call_count: call_count.clone(),
    });

    engine.add_rule_policy("target_rule", action).await;

    let alert = Alert::new(
        "target_rule",
        "Target Rule",
        AlertSeverity::Info,
        "Test description",
        "1.1.1.1",
        vec![]
    );

    engine.handle_alert(&alert).await;

    // Wait a short bit
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let final_count = *call_count.lock().await;
    assert_eq!(final_count, 1);
}

#[tokio::test]
async fn test_response_engine_no_trigger_on_mismatch() {
    let engine = ResponseEngine::new();
    let call_count = Arc::new(Mutex::new(0));
    let action = Arc::new(MockAction {
        name: "test_action".to_string(),
        call_count: call_count.clone(),
    });

    engine.add_severity_policy(AlertSeverity::Critical, action).await;

    let alert = Alert::new(
        "rule_1",
        "Test Rule",
        AlertSeverity::Low,
        "Test description",
        "1.1.1.1",
        vec![]
    );

    engine.handle_alert(&alert).await;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let final_count = *call_count.lock().await;
    assert_eq!(final_count, 0);
}
