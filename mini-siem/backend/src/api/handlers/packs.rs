use actix_web::{get, post, web, HttpMessage, HttpRequest, HttpResponse, Responder};
use chrono::Utc;
use serde::Serialize;
use uuid::Uuid;

use crate::api::server::AppState;
use crate::api::tenant::enforce_tenant_fixed_window;
use crate::auth::jwt::Claims;
use crate::db::models::audit::AuditEvent;
use crate::db::models::rule::{DetectionRule, RuleCreate};
use crate::utils::audit::{audit_payload, hash_audit_payload, sign_audit_hash};

#[derive(Clone)]
struct PackRuleTemplate {
    name: &'static str,
    description: &'static str,
    rule_type: &'static str,
    severity: &'static str,
    threshold: Option<i32>,
    window_seconds: Option<i32>,
    condition: serde_json::Value,
    validated: bool,
}

#[derive(Clone, Serialize)]
struct PackPlaybookStep {
    title: &'static str,
    action_type: &'static str,
    owner_role: &'static str,
    automated: bool,
    description: &'static str,
}

#[derive(Clone)]
struct PackTemplate {
    slug: &'static str,
    vertical: &'static str,
    name: &'static str,
    description: &'static str,
    enrichment: serde_json::Value,
    playbook: Vec<PackPlaybookStep>,
    rules: Vec<PackRuleTemplate>,
}

#[derive(Serialize)]
struct PackRuleResponse {
    name: String,
    description: String,
    rule_type: String,
    severity: String,
    threshold: Option<i32>,
    window_seconds: Option<i32>,
    condition: serde_json::Value,
    validated: bool,
    installed_rule_id: Option<Uuid>,
}

#[derive(Serialize)]
struct DetectionPackResponse {
    slug: String,
    vertical: String,
    name: String,
    description: String,
    enrichment: serde_json::Value,
    playbook: Vec<PackPlaybookStep>,
    rules: Vec<PackRuleResponse>,
    installed: bool,
    installed_rule_count: usize,
    total_rule_count: usize,
}

fn curated_packs() -> Vec<PackTemplate> {
    vec![
        PackTemplate {
            slug: "cloud-iam-abuse",
            vertical: "Cloud IAM Abuse",
            name: "Cloud IAM Abuse Pack",
            description: "Detect privilege escalation, risky logins, and access-key abuse across cloud identity systems.",
            enrichment: serde_json::json!({
                "focus": ["cloud provider", "identity", "session context", "source IP reputation"],
                "enrichment_sources": ["cloud trail / audit logs", "asset inventory", "geoip", "mfa posture"],
                "validated": true
            }),
            playbook: vec![
                PackPlaybookStep { title: "Freeze the session", action_type: "containment", owner_role: "analyst", automated: false, description: "Revoke active sessions and temporary credentials." },
                PackPlaybookStep { title: "Review identity changes", action_type: "investigate", owner_role: "cloud-admin", automated: false, description: "Audit role changes, policy attachments, and MFA posture." },
                PackPlaybookStep { title: "Preserve evidence", action_type: "collect", owner_role: "analyst", automated: true, description: "Capture audit trail and timeline notes for postmortem use." },
            ],
            rules: vec![
                PackRuleTemplate {
                    name: "Cloud IAM - Privilege Escalation",
                    description: "Detect role, policy, or group changes that can elevate cloud access.",
                    rule_type: "generic",
                    severity: "HIGH",
                    threshold: None,
                    window_seconds: None,
                    condition: serde_json::json!({
                        "any": [
                            {"field": "message", "op": "contains", "value": "AttachUserPolicy"},
                            {"field": "message", "op": "contains", "value": "PutUserPolicy"},
                            {"field": "message", "op": "contains", "value": "CreatePolicyVersion"},
                            {"field": "message", "op": "contains", "value": "AddUserToGroup"},
                            {"field": "event_type", "op": "==", "value": "iam_privilege_change"}
                        ]
                    }),
                    validated: true,
                },
                PackRuleTemplate {
                    name: "Cloud IAM - Suspicious Console Login",
                    description: "Detect successful cloud console logins without MFA or from unusual context.",
                    rule_type: "generic",
                    severity: "MEDIUM",
                    threshold: None,
                    window_seconds: None,
                    condition: serde_json::json!({
                        "all": [
                            {"field": "event_type", "op": "==", "value": "login_success"},
                            {"field": "message", "op": "contains", "value": "ConsoleLogin"},
                            {"field": "mfa_used", "op": "==", "value": false}
                        ]
                    }),
                    validated: true,
                },
                PackRuleTemplate {
                    name: "Cloud IAM - New Access Key Issued",
                    description: "Detect creation of new access keys that can extend attacker dwell time.",
                    rule_type: "generic",
                    severity: "HIGH",
                    threshold: None,
                    window_seconds: None,
                    condition: serde_json::json!({
                        "any": [
                            {"field": "message", "op": "contains", "value": "CreateAccessKey"},
                            {"field": "message", "op": "contains", "value": "UpdateAccessKey"},
                            {"field": "event_type", "op": "==", "value": "iam_access_key_created"}
                        ]
                    }),
                    validated: true,
                },
            ],
        },
        PackTemplate {
            slug: "endpoint-ransomware-precursors",
            vertical: "Endpoint Ransomware Precursors",
            name: "Endpoint Ransomware Precursors Pack",
            description: "Catch the process, script, and file-system activity that usually appears before encryption.",
            enrichment: serde_json::json!({
                "focus": ["hostname", "user", "process tree", "endpoint isolation", "backup health"],
                "enrichment_sources": ["EDR telemetry", "process ancestry", "file activity", "command line"],
                "validated": true
            }),
            playbook: vec![
                PackPlaybookStep { title: "Isolate the endpoint", action_type: "containment", owner_role: "soc", automated: false, description: "Use EDR or network controls to stop spread." },
                PackPlaybookStep { title: "Kill malicious processes", action_type: "response", owner_role: "soc", automated: false, description: "Terminate the script or process chain driving encryption." },
                PackPlaybookStep { title: "Collect volatile evidence", action_type: "collect", owner_role: "forensics", automated: true, description: "Capture command line, memory, and process tree details." },
            ],
            rules: vec![
                PackRuleTemplate {
                    name: "Endpoint - Suspicious PowerShell Encoded Command",
                    description: "Detect PowerShell execution using encoded or obfuscated commands.",
                    rule_type: "generic",
                    severity: "HIGH",
                    threshold: None,
                    window_seconds: None,
                    condition: serde_json::json!({
                        "any": [
                            {"field": "message", "op": "contains", "value": "powershell"},
                            {"field": "message", "op": "contains", "value": "-enc"},
                            {"field": "message", "op": "contains", "value": "-encodedcommand"}
                        ]
                    }),
                    validated: true,
                },
                PackRuleTemplate {
                    name: "Endpoint - Shadow Copy Deletion",
                    description: "Detect commands used to delete backups or shadow copies before encryption.",
                    rule_type: "generic",
                    severity: "CRITICAL",
                    threshold: None,
                    window_seconds: None,
                    condition: serde_json::json!({
                        "any": [
                            {"field": "message", "op": "contains", "value": "vssadmin delete shadows"},
                            {"field": "message", "op": "contains", "value": "wmic shadowcopy delete"},
                            {"field": "message", "op": "contains", "value": "bcdedit /set"}
                        ]
                    }),
                    validated: true,
                },
                PackRuleTemplate {
                    name: "Endpoint - Mass File Rename Or Encryption Extension",
                    description: "Detect bursty file rename activity or common ransomware file extensions.",
                    rule_type: "generic",
                    severity: "CRITICAL",
                    threshold: Some(25),
                    window_seconds: Some(300),
                    condition: serde_json::json!({
                        "any": [
                            {"field": "message", "op": "contains", "value": ".locked"},
                            {"field": "message", "op": "contains", "value": ".encrypted"},
                            {"field": "message", "op": "contains", "value": "file renamed"},
                            {"field": "event_type", "op": "==", "value": "file_rename_burst"}
                        ]
                    }),
                    validated: true,
                },
            ],
        },
        PackTemplate {
            slug: "insider-risk",
            vertical: "Insider Risk",
            name: "Insider Risk Pack",
            description: "Spot suspicious access bursts, archive staging, and off-hours collection activity.",
            enrichment: serde_json::json!({
                "focus": ["user role", "device trust", "asset criticality", "data classification", "HR status"],
                "enrichment_sources": ["identity provider", "DLP", "asset inventory", "calendar / shift data"],
                "validated": true
            }),
            playbook: vec![
                PackPlaybookStep { title: "Validate business context", action_type: "investigate", owner_role: "manager", automated: false, description: "Check whether the access pattern aligns with a project or approved task." },
                PackPlaybookStep { title: "Preserve evidence", action_type: "collect", owner_role: "analyst", automated: true, description: "Capture downloads, file paths, and access timelines for review." },
                PackPlaybookStep { title: "Escalate if needed", action_type: "escalate", owner_role: "soc", automated: false, description: "Route the case to HR, security leadership, or legal as needed." },
            ],
            rules: vec![
                PackRuleTemplate {
                    name: "Insider - Large Data Exfiltration",
                    description: "Detect unusually large transfers or downloads from sensitive sources.",
                    rule_type: "generic",
                    severity: "HIGH",
                    threshold: Some(500),
                    window_seconds: Some(900),
                    condition: serde_json::json!({
                        "any": [
                            {"field": "event_type", "op": "==", "value": "large_download"},
                            {"field": "message", "op": "contains", "value": "rclone"},
                            {"field": "message", "op": "contains", "value": "mega.nz"},
                            {"field": "bytes_out", "op": ">=", "value": 500000000}
                        ]
                    }),
                    validated: true,
                },
                PackRuleTemplate {
                    name: "Insider - Off Hours Privileged Access",
                    description: "Detect privileged access outside normal working windows or shift hours.",
                    rule_type: "generic",
                    severity: "MEDIUM",
                    threshold: None,
                    window_seconds: None,
                    condition: serde_json::json!({
                        "all": [
                            {"field": "event_type", "op": "==", "value": "privileged_access"},
                            {"field": "off_hours", "op": "==", "value": true}
                        ]
                    }),
                    validated: true,
                },
                PackRuleTemplate {
                    name: "Insider - Archive Tool Staging",
                    description: "Detect use of archive tools commonly used to stage exfiltration packages.",
                    rule_type: "generic",
                    severity: "MEDIUM",
                    threshold: None,
                    window_seconds: None,
                    condition: serde_json::json!({
                        "any": [
                            {"field": "message", "op": "contains", "value": "7z"},
                            {"field": "message", "op": "contains", "value": "rar"},
                            {"field": "message", "op": "contains", "value": "zip -r"},
                            {"field": "message", "op": "contains", "value": "archive"}
                        ]
                    }),
                    validated: true,
                },
            ],
        },
    ]
}

fn pack_summary(
    _tenant_id: &str,
    pack: &PackTemplate,
    installed_rules: &[DetectionRule],
) -> DetectionPackResponse {
    let mut rule_responses = Vec::with_capacity(pack.rules.len());
    let mut installed_rule_count = 0usize;

    for template in &pack.rules {
        let installed_rule = installed_rules.iter().find(|rule| rule.name == template.name);
        if installed_rule.is_some() {
            installed_rule_count += 1;
        }

        rule_responses.push(PackRuleResponse {
            name: template.name.to_string(),
            description: template.description.to_string(),
            rule_type: template.rule_type.to_string(),
            severity: template.severity.to_string(),
            threshold: template.threshold,
            window_seconds: template.window_seconds,
            condition: template.condition.clone(),
            validated: template.validated,
            installed_rule_id: installed_rule.map(|rule| rule.id),
        });
    }

    DetectionPackResponse {
        slug: pack.slug.to_string(),
        vertical: pack.vertical.to_string(),
        name: pack.name.to_string(),
        description: pack.description.to_string(),
        enrichment: pack.enrichment.clone(),
        playbook: pack.playbook.clone(),
        rules: rule_responses,
        installed: installed_rule_count == pack.rules.len(),
        installed_rule_count,
        total_rule_count: pack.rules.len(),
    }
}

async fn record_pack_audit(
    state: &AppState,
    claims: &Claims,
    action: &str,
    resource_id: Option<&str>,
    metadata: serde_json::Value,
) -> Result<(), HttpResponse> {
    let payload = audit_payload(
        &claims.tenant_id,
        &claims.sub,
        &claims.email,
        &claims.roles,
        action,
        "detection_pack",
        resource_id,
        None,
        claims.jti.as_deref(),
        metadata,
    );

    let previous_hash = state.db.latest_audit_hash(&claims.tenant_id).await.map_err(|e| {
        HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("audit chain lookup failed: {}", e)}))
    })?;
    let event_hash = hash_audit_payload(previous_hash.as_deref(), &payload).map_err(|e| {
        HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("audit hash failed: {}", e)}))
    })?;
    let signature = sign_audit_hash(&state.audit_signing_key, &event_hash).map_err(|e| {
        HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("audit signature failed: {}", e)}))
    })?;

    let event = AuditEvent {
        id: Uuid::new_v4(),
        tenant_id: claims.tenant_id.clone(),
        actor_user_id: claims.sub.clone(),
        actor_email: claims.email.clone(),
        actor_roles: claims.roles.clone(),
        action: action.to_string(),
        resource_type: "detection_pack".to_string(),
        resource_id: resource_id.map(|value| value.to_string()),
        target_tenant_id: None,
        request_id: claims.jti.clone(),
        metadata: payload,
        previous_hash,
        event_hash,
        signature,
        created_at: Utc::now(),
    };

    state.db.insert_audit_event(&event).await.map_err(|e| {
        HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("audit write failed: {}", e)}))
    })?;

    Ok(())
}

async fn ensure_pack_rules(state: &AppState, tenant_id: &str, pack: &PackTemplate) -> Result<Vec<DetectionRule>, HttpResponse> {
    let existing_rules = state.db.get_all_rules(tenant_id).await.map_err(|e| {
        HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to load rules: {}", e)}))
    })?;

    for template in &pack.rules {
        if existing_rules.iter().any(|rule| rule.name == template.name) {
            continue;
        }

        let rule = RuleCreate {
            tenant_id: tenant_id.to_string(),
            name: template.name.to_string(),
            description: Some(template.description.to_string()),
            rule_type: template.rule_type.to_string(),
            severity: template.severity.to_string(),
            threshold: template.threshold,
            window_seconds: template.window_seconds,
            condition: Some(template.condition.clone()),
        };

        state.db.create_rule(&rule).await.map_err(|e| {
            HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to install pack rule '{}': {}", template.name, e)}))
        })?;
    }

    let refreshed_rules = state.db.get_all_rules(tenant_id).await.map_err(|e| {
        HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to refresh rules: {}", e)}))
    })?;

    Ok(refreshed_rules)
}

fn require_pack_roles(claims: &Claims) -> bool {
    claims.roles.contains(&"analyst".to_string()) || claims.roles.contains(&"admin".to_string())
}

#[get("/detection-packs")]
pub async fn list_detection_packs(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !require_pack_roles(&claims) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "insufficient role"}));
    }

    if let Err(response) = enforce_tenant_fixed_window(
        &state,
        &claims.tenant_id,
        "api_requests",
        state.tenant_limits.api_requests_per_minute,
        1,
    ).await {
        return response;
    }

    let packs = curated_packs();
    let rules = match state.db.get_all_rules(&claims.tenant_id).await {
        Ok(rules) => rules,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to load rules: {}", e)})),
    };

    let responses: Vec<_> = packs.iter().map(|pack| pack_summary(&claims.tenant_id, pack, &rules)).collect();
    HttpResponse::Ok().json(responses)
}

#[get("/detection-packs/{slug}")]
pub async fn get_detection_pack(req: HttpRequest, state: web::Data<AppState>, slug: web::Path<String>) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !require_pack_roles(&claims) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "insufficient role"}));
    }

    let Some(pack) = curated_packs().into_iter().find(|pack| pack.slug == slug.as_str()) else {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "detection pack not found"}));
    };

    match state.db.get_all_rules(&claims.tenant_id).await {
        Ok(rules) => HttpResponse::Ok().json(pack_summary(&claims.tenant_id, &pack, &rules)),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to load rules: {}", e)})),
    }
}

#[post("/detection-packs/{slug}/install")]
pub async fn install_detection_pack(req: HttpRequest, state: web::Data<AppState>, slug: web::Path<String>) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !require_pack_roles(&claims) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "insufficient role"}));
    }

    if let Err(response) = enforce_tenant_fixed_window(
        &state,
        &claims.tenant_id,
        "rule_mutations",
        state.tenant_limits.rule_mutations_per_minute,
        1,
    ).await {
        return response;
    }

    let Some(pack) = curated_packs().into_iter().find(|pack| pack.slug == slug.as_str()) else {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "detection pack not found"}));
    };

    let rules = match ensure_pack_rules(&state, &claims.tenant_id, &pack).await {
        Ok(rules) => rules,
        Err(response) => return response,
    };

    let _ = record_pack_audit(
        &state,
        &claims,
        "detection_pack.install",
        Some(pack.slug),
        serde_json::json!({
            "name": pack.name,
            "vertical": pack.vertical,
            "rule_count": pack.rules.len(),
        }),
    ).await;

    HttpResponse::Ok().json(pack_summary(&claims.tenant_id, &pack, &rules))
}