use crate::types::{Log, EcsLog};
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    static ref SSH_ACCEPTED_RE: Regex = Regex::new(r"Accepted password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)").unwrap();
    static ref SSH_FAILED_RE: Regex = Regex::new(r"Failed password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)").unwrap();
}

pub fn normalize_log(log: &Log) -> EcsLog {
    let mut ecs = EcsLog::new();
    ecs.timestamp = log.timestamp;
    ecs.event_id = log.id;
    ecs.message = Some(log.message.clone());
    ecs.event_original = Some(log.message.clone());
    ecs.source_ip = Some(log.source_ip.clone());
    
    // Map severity
    ecs.log_level = Some(log.severity.to_string());
    
    // Default kind
    ecs.event_kind = Some("event".to_string());

    // Basic heuristic normalization
    if log.is_failed_login() {
        ecs.event_category.push("authentication".to_string());
        ecs.event_type.push("authentication_failure".to_string());
        ecs.event_outcome = Some("failure".to_string());
    } else if log.is_successful_login() {
        ecs.event_category.push("authentication".to_string());
        ecs.event_type.push("authentication_success".to_string());
        ecs.event_outcome = Some("success".to_string());
    }

    // Service specific parsing
    if let Some(service) = &log.service {
        ecs.labels.insert("service".to_string(), service.clone());
        
        if service == "ssh" || service == "sshd" {
            parse_ssh_log(&log.message, &mut ecs);
        }
    }

    // User mapping
    if let Some(user) = &log.target_user {
        ecs.user_name = Some(user.clone());
    }

    ecs
}

fn parse_ssh_log(message: &str, ecs: &mut EcsLog) {
    if let Some(caps) = SSH_ACCEPTED_RE.captures(message) {
        ecs.user_name = caps.name("user").map(|m| m.as_str().to_string());
        ecs.source_ip = caps.name("ip").map(|m| m.as_str().to_string());
        ecs.source_port = caps.name("port").and_then(|m| m.as_str().parse().ok());
    } else if let Some(caps) = SSH_FAILED_RE.captures(message) {
        ecs.user_name = caps.name("user").map(|m| m.as_str().to_string());
        ecs.source_ip = caps.name("ip").map(|m| m.as_str().to_string());
        ecs.source_port = caps.name("port").and_then(|m| m.as_str().parse().ok());
    }
}
