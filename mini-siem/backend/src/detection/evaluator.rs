use crate::types::Log;
use crate::utils::normalization::normalize_log;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum RuleCondition {
    All(Vec<RuleCondition>),
    Any(Vec<RuleCondition>),
    Not(Box<RuleCondition>),
    Field {
        field: String,
        op: String,
        value: Value,
    },
}

impl RuleCondition {
    pub fn evaluate(&self, log: &Log) -> bool {
        match self {
            RuleCondition::All(conditions) => conditions.iter().all(|c| c.evaluate(log)),
            RuleCondition::Any(conditions) => conditions.iter().any(|c| c.evaluate(log)),
            RuleCondition::Not(condition) => !condition.evaluate(log),
            RuleCondition::Field { field, op, value } => {
                // First try ECS fields (normalized)
                let ecs = normalize_log(log);
                let log_value = match field.as_str() {
                    // ECS mapping
                    "user.name" => ecs.user_name.map(Value::String).unwrap_or(Value::Null),
                    "source.ip" => ecs.source_ip.map(Value::String).unwrap_or(Value::Null),
                    "event.outcome" => ecs.event_outcome.map(Value::String).unwrap_or(Value::Null),
                    "log.level" => ecs.log_level.map(Value::String).unwrap_or(Value::Null),
                    
                    // Fallback to original fields
                    "event_type" => Value::String(log.event_type.clone()),
                    "source_ip" => Value::String(log.source_ip.clone()),
                    "target_user" => log.target_user.as_ref().map(|s| Value::String(s.clone())).unwrap_or(Value::Null),
                    "service" => log.service.as_ref().map(|s| Value::String(s.clone())).unwrap_or(Value::Null),
                    "message" => Value::String(log.message.clone()),
                    "severity" => Value::String(log.severity.to_string()),
                    _ => {
                        // Check metadata
                        log.metadata.get(field).cloned().unwrap_or(Value::Null)
                    }
                };

                match op.as_str() {
                    "==" | "eq" => &log_value == value,
                    "!=" | "ne" => &log_value != value,
                    "contains" => {
                        if let (Some(l_str), Some(v_str)) = (log_value.as_str(), value.as_str()) {
                            let l_str: &str = l_str;
                            l_str.contains(v_str)
                        } else {
                            false
                        }
                    }
                    "startswith" => {
                        if let (Some(l_str), Some(v_str)) = (log_value.as_str(), value.as_str()) {
                            let l_str: &str = l_str;
                            l_str.starts_with(v_str)
                        } else {
                            false
                        }
                    }
                    "endswith" => {
                        if let (Some(l_str), Some(v_str)) = (log_value.as_str(), value.as_str()) {
                            let l_str: &str = l_str;
                            l_str.ends_with(v_str)
                        } else {
                            false
                        }
                    }
                    ">" | "gt" => compare_json_values(&log_value, value) == Some(std::cmp::Ordering::Greater),
                    "<" | "lt" => compare_json_values(&log_value, value) == Some(std::cmp::Ordering::Less),
                    ">=" | "ge" => matches!(compare_json_values(&log_value, value), Some(std::cmp::Ordering::Greater) | Some(std::cmp::Ordering::Equal)),
                    "<=" | "le" => matches!(compare_json_values(&log_value, value), Some(std::cmp::Ordering::Less) | Some(std::cmp::Ordering::Equal)),
                    _ => false,
                }
            }
        }
    }
}

fn compare_json_values(a: &Value, b: &Value) -> Option<std::cmp::Ordering> {
    if let (Some(a_num), Some(b_num)) = (a.as_f64(), b.as_f64()) {
        a_num.partial_cmp(&b_num)
    } else if let (Some(a_str), Some(b_str)) = (a.as_str(), b.as_str()) {
        Some(a_str.cmp(b_str))
    } else {
        None
    }
}
