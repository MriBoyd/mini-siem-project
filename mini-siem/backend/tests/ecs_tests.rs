use mini_siem::types::Log;
use mini_siem::detection::evaluator::RuleCondition;
use mini_siem::detection::rules::generic::GenericRule;
use mini_siem::detection::rules::Rule;
use serde_json::json;

#[tokio::test]
async fn test_ecs_normalization_rule() {
    // This rule uses ECS field "user.name" instead of original "target_user"
    // and "event.outcome" instead of custom heuristics in the rule itself.
    let condition = RuleCondition::All(vec![
        RuleCondition::Field {
            field: "user.name".to_string(),
            op: "==".to_string(),
            value: json!("admin"),
        },
        RuleCondition::Field {
            field: "event.outcome".to_string(),
            op: "==".to_string(),
            value: json!("success"),
        },
    ]);
    
    let rule = GenericRule::new(
        "ecs_rule_1".to_string(),
        "Successful Admin Login".to_string(),
        "Medium".to_string(),
        condition,
    );

    // Case 1: SSH accepted log (matches ECS parser)
    let log = Log::new(
        "ssh".to_string(),
        "1.2.3.4".to_string(),
        "Accepted password for admin from 1.2.3.4 port 22 ssh2".to_string(),
    );
    // Explicitly set service so the parser knows it's ssh
    let mut log = log;
    log.service = Some("ssh".to_string());
    
    let res = rule.evaluate(&log).await.unwrap();
    assert!(res.is_some(), "Should match on normalized user.name and event.outcome");

    // Case 2: Different format but same meaning (target_user set)
    let mut log2 = Log::new(
        "login_success".to_string(),
        "1.2.3.4".to_string(),
        "User admin logged in".to_string(),
    );
    log2.target_user = Some("admin".to_string());
    
    let res2 = rule.evaluate(&log2).await.unwrap();
    assert!(res2.is_some(), "Should match on target_user mapped to user.name");
}

#[tokio::test]
async fn test_source_ip_mapping() {
    let condition = RuleCondition::Field {
        field: "source.ip".to_string(),
        op: "==".to_string(),
        value: json!("8.8.8.8"),
    };
    
    let rule = GenericRule::new(
        "ecs_rule_2".to_string(),
        "Source IP Check".to_string(),
        "Low".to_string(),
        condition,
    );

    let log = Log::new(
        "test".to_string(),
        "8.8.8.8".to_string(),
        "some message".to_string(),
    );
    
    let res = rule.evaluate(&log).await.unwrap();
    assert!(res.is_some(), "Should match on source.ip mapped from source_ip");
}
