use mini_siem::types::{Log, LogSeverity};
use mini_siem::detection::evaluator::RuleCondition;
use mini_siem::detection::rules::generic::GenericRule;
use mini_siem::detection::rules::Rule;
use serde_json::json;

#[tokio::test]
async fn test_generic_rule_simple_field() {
    let condition = RuleCondition::Field {
        field: "message".to_string(),
        op: "contains".to_string(),
        value: json!("powershell -e"),
    };
    
    let rule = GenericRule::new(
        "rule_gen_1".to_string(),
        "Suspicious PowerShell".to_string(),
        "High".to_string(),
        condition,
    );

    let mut log = Log::new(
        "process_start".to_string(),
        "10.0.0.5".to_string(),
        "User executed powershell -e base64payload".to_string(),
    );
    
    // Should trigger
    let res = rule.evaluate(&log).await.unwrap();
    assert!(res.is_some());
    let alert = res.unwrap();
    assert_eq!(alert.rule_name, "Suspicious PowerShell");

    // Should not trigger
    log.message = "User executed ls -la".to_string();
    let res = rule.evaluate(&log).await.unwrap();
    assert!(res.is_none());
}

#[tokio::test]
async fn test_generic_rule_complex_condition() {
    // (event_type == "login_failed" AND severity == "CRITICAL") OR source_ip == "192.168.1.100"
    let condition = RuleCondition::Any(vec![
        RuleCondition::All(vec![
            RuleCondition::Field {
                field: "event_type".to_string(),
                op: "==".to_string(),
                value: json!("login_failed"),
            },
            RuleCondition::Field {
                field: "severity".to_string(),
                op: "==".to_string(),
                value: json!("CRITICAL"),
            },
        ]),
        RuleCondition::Field {
            field: "source_ip".to_string(),
            op: "==".to_string(),
            value: json!("192.168.1.100"),
        },
    ]);

    let rule = GenericRule::new(
        "rule_gen_2".to_string(),
        "Complex Rule".to_string(),
        "Medium".to_string(),
        condition,
    );

    // Case 1: Matches first part of OR (both parts of AND)
    let mut log = Log::new(
        "login_failed".to_string(),
        "1.1.1.1".to_string(),
        "Failed login".to_string(),
    );
    log.severity = LogSeverity::Critical;
    assert!(rule.evaluate(&log).await.unwrap().is_some());

    // Case 2: Matches second part of OR
    let mut log2 = Log::new(
        "info_event".to_string(),
        "192.168.1.100".to_string(),
        "Regular activity".to_string(),
    );
    log2.severity = LogSeverity::Info;
    assert!(rule.evaluate(&log2).await.unwrap().is_some());

    // Case 3: No match
    let mut log3 = Log::new(
        "login_failed".to_string(),
        "1.1.1.1".to_string(),
        "Failed login".to_string(),
    );
    log3.severity = LogSeverity::Low;
    assert!(rule.evaluate(&log3).await.unwrap().is_none());
}

#[tokio::test]
async fn test_generic_rule_metadata() {
    let condition = RuleCondition::Field {
        field: "process_id".to_string(),
        op: "==".to_string(),
        value: json!(1234),
    };

    let rule = GenericRule::new(
        "rule_gen_3".to_string(),
        "Metadata Rule".to_string(),
        "Low".to_string(),
        condition,
    );

    let mut log = Log::new(
        "test".to_string(),
        "127.0.0.1".to_string(),
        "test message".to_string(),
    );
    
    // No metadata yet
    assert!(rule.evaluate(&log).await.unwrap().is_none());

    // With metadata
    log.metadata = json!({"process_id": 1234, "user": "admin"});
    assert!(rule.evaluate(&log).await.unwrap().is_some());

    // Wrong metadata value
    log.metadata = json!({"process_id": 5678});
    assert!(rule.evaluate(&log).await.unwrap().is_none());
}
