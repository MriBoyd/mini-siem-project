use actix_web::{get, put, post, web, HttpRequest, HttpMessage, HttpResponse, Responder};
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::api::server::AppState;
use crate::api::tenant::enforce_tenant_fixed_window;
use crate::auth::jwt::Claims;
use crate::db::models::audit::AuditEvent;
use crate::db::models::compliance::{AccessReviewUser, ComplianceEvidenceBundle};
use crate::utils::audit::{audit_payload, hash_audit_payload, sign_audit_hash};

#[derive(Debug, serde::Deserialize)]
pub struct CompliancePolicyRequest {
    pub retention_days: Option<i32>,
    pub legal_hold: Option<bool>,
    pub legal_hold_reason: Option<String>,
    pub legal_hold_until: Option<chrono::DateTime<Utc>>,
    pub access_review_interval_days: Option<i32>,
    pub key_rotation_interval_days: Option<i32>,
    pub evidence_export_enabled: Option<bool>,
}

#[derive(Debug, serde::Deserialize)]
pub struct EvidenceQuery {
    pub tenant_id: Option<String>,
}

async fn record_compliance_audit(
    state: &AppState,
    claims: &Claims,
    action: &str,
    target_tenant_id: Option<&str>,
    metadata: serde_json::Value,
) -> Result<(), HttpResponse> {
    let payload = audit_payload(
        &claims.tenant_id,
        &claims.sub,
        &claims.email,
        &claims.roles,
        action,
        "compliance",
        None,
        target_tenant_id,
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
        resource_type: "compliance".to_string(),
        resource_id: None,
        target_tenant_id: target_tenant_id.map(|value| value.to_string()),
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

fn access_review_summary(users: &[AccessReviewUser], audit_events: &[AuditEvent]) -> serde_json::Value {
    let admin_count = users.iter().filter(|user| user.role == "admin").count();
    let analyst_count = users.iter().filter(|user| user.role == "analyst").count();
    let user_count = users.len();
    let recent_admin_actions = audit_events.iter().filter(|event| event.actor_roles.iter().any(|role| role == "admin")).count();

    serde_json::json!({
        "user_count": user_count,
        "admin_count": admin_count,
        "analyst_count": analyst_count,
        "recent_admin_actions": recent_admin_actions,
        "users": users,
    })
}

#[get("/admin/compliance/policy")]
pub async fn get_policy(req: HttpRequest, state: web::Data<AppState>, query: web::Query<EvidenceQuery>) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !claims.roles.iter().any(|role| role == "admin") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }

    if let Err(response) = enforce_tenant_fixed_window(&state, &claims.tenant_id, "api_requests", state.tenant_limits.api_requests_per_minute, 1).await {
        return response;
    }

    let target_tenant_id = query.tenant_id.clone().unwrap_or_else(|| claims.tenant_id.clone());
    match state.db.get_tenant_compliance_policy(&target_tenant_id).await {
        Ok(policy) => HttpResponse::Ok().json(policy),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to load policy: {}", e)})),
    }
}

#[put("/admin/compliance/policy")]
pub async fn update_policy(req: HttpRequest, state: web::Data<AppState>, query: web::Query<EvidenceQuery>, body: web::Json<CompliancePolicyRequest>) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !claims.roles.iter().any(|role| role == "admin") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }

    if let Err(response) = enforce_tenant_fixed_window(&state, &claims.tenant_id, "rule_mutations", state.tenant_limits.rule_mutations_per_minute, 1).await {
        return response;
    }

    let target_tenant_id = query.tenant_id.clone().unwrap_or_else(|| claims.tenant_id.clone());
    let mut policy = match state.db.get_tenant_compliance_policy(&target_tenant_id).await {
        Ok(policy) => policy,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to load policy: {}", e)})),
    };

    if let Some(value) = body.retention_days { policy.retention_days = value.max(1); }
    if let Some(value) = body.legal_hold { policy.legal_hold = value; }
    if let Some(value) = &body.legal_hold_reason { policy.legal_hold_reason = Some(value.clone()); }
    if let Some(value) = body.legal_hold_until { policy.legal_hold_until = Some(value); }
    if let Some(value) = body.access_review_interval_days { policy.access_review_interval_days = value.max(1); }
    if let Some(value) = body.key_rotation_interval_days { policy.key_rotation_interval_days = value.max(1); }
    if let Some(value) = body.evidence_export_enabled { policy.evidence_export_enabled = value; }

    policy.updated_at = Utc::now();

    let record = match state.db.upsert_tenant_compliance_policy(&policy).await {
        Ok(policy) => policy,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to save policy: {}", e)})),
    };

    if let Err(response) = record_compliance_audit(&state, &claims, "compliance.policy.update", Some(&target_tenant_id), serde_json::json!({"policy": record})).await {
        return response;
    }

    HttpResponse::Ok().json(record)
}

#[post("/admin/compliance/key-rotation")]
pub async fn record_key_rotation(req: HttpRequest, state: web::Data<AppState>, query: web::Query<EvidenceQuery>) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !claims.roles.iter().any(|role| role == "admin") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }

    if let Err(response) = enforce_tenant_fixed_window(&state, &claims.tenant_id, "rule_mutations", state.tenant_limits.rule_mutations_per_minute, 1).await {
        return response;
    }

    let target_tenant_id = query.tenant_id.clone().unwrap_or_else(|| claims.tenant_id.clone());
    let mut policy = match state.db.get_tenant_compliance_policy(&target_tenant_id).await {
        Ok(policy) => policy,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to load policy: {}", e)})),
    };
    policy.last_key_rotation_at = Some(Utc::now());
    policy.updated_at = Utc::now();

    let record = match state.db.upsert_tenant_compliance_policy(&policy).await {
        Ok(policy) => policy,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to save policy: {}", e)})),
    };

    if let Err(response) = record_compliance_audit(&state, &claims, "compliance.key_rotation.record", Some(&target_tenant_id), serde_json::json!({"policy": record})).await {
        return response;
    }

    HttpResponse::Ok().json(record)
}

#[get("/admin/access-review")]
pub async fn access_review(req: HttpRequest, state: web::Data<AppState>, query: web::Query<EvidenceQuery>) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !claims.roles.iter().any(|role| role == "admin") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }

    if let Err(response) = enforce_tenant_fixed_window(&state, &claims.tenant_id, "audit_queries", state.tenant_limits.audit_queries_per_minute, 1).await {
        return response;
    }

    let target_tenant_id = query.tenant_id.clone().unwrap_or_else(|| claims.tenant_id.clone());
    let users = match state.db.list_users_by_tenant(&target_tenant_id).await {
        Ok(users) => users.into_iter().map(|user| AccessReviewUser {
            id: user.id,
            tenant_id: user.tenant_id,
            email: user.email,
            role: user.role,
        }).collect::<Vec<_>>(),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to load users: {}", e)})),
    };
    let audit_events = match state.db.list_audit_events_since(&target_tenant_id, Utc::now() - Duration::days(90)).await {
        Ok(events) => events,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to load audit events: {}", e)})),
    };

    if let Err(response) = record_compliance_audit(&state, &claims, "compliance.access_review.view", Some(&target_tenant_id), serde_json::json!({"user_count": users.len()})).await {
        return response;
    }

    HttpResponse::Ok().json(access_review_summary(&users, &audit_events))
}

#[get("/admin/compliance/evidence")]
pub async fn evidence_bundle(req: HttpRequest, state: web::Data<AppState>, query: web::Query<EvidenceQuery>) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !claims.roles.iter().any(|role| role == "admin") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }

    if let Err(response) = enforce_tenant_fixed_window(&state, &claims.tenant_id, "audit_queries", state.tenant_limits.audit_queries_per_minute, 1).await {
        return response;
    }

    let target_tenant_id = query.tenant_id.clone().unwrap_or_else(|| claims.tenant_id.clone());
    let policy = match state.db.get_tenant_compliance_policy(&target_tenant_id).await {
        Ok(policy) => policy,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to load policy: {}", e)})),
    };
    let users = match state.db.list_users_by_tenant(&target_tenant_id).await {
        Ok(users) => users.into_iter().map(|user| AccessReviewUser {
            id: user.id,
            tenant_id: user.tenant_id,
            email: user.email,
            role: user.role,
        }).collect::<Vec<_>>(),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to load users: {}", e)})),
    };
    let audit_since = Utc::now() - Duration::days(30);
    let audit_events = match state.db.list_audit_events_since(&target_tenant_id, audit_since).await {
        Ok(events) => events,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to load audit events: {}", e)})),
    };
    let access_review_report = access_review_summary(&users, &audit_events);
    let audit_summary = serde_json::json!({
        "event_count": audit_events.len(),
        "window_days": 30,
        "recent_actions": audit_events.iter().take(10).map(|event| serde_json::json!({
            "action": event.action,
            "actor_email": event.actor_email,
            "created_at": event.created_at,
        })).collect::<Vec<_>>(),
    });
    let retention_summary = serde_json::json!({
        "retention_days": policy.retention_days,
        "legal_hold": policy.legal_hold,
        "legal_hold_reason": policy.legal_hold_reason,
        "legal_hold_until": policy.legal_hold_until,
        "key_rotation_interval_days": policy.key_rotation_interval_days,
        "last_key_rotation_at": policy.last_key_rotation_at,
        "evidence_export_enabled": policy.evidence_export_enabled,
    });

    if let Err(response) = record_compliance_audit(&state, &claims, "compliance.evidence.export", Some(&target_tenant_id), serde_json::json!({"event_count": audit_events.len()})).await {
        return response;
    }

    let bundle = ComplianceEvidenceBundle {
        tenant_id: target_tenant_id,
        generated_at: Utc::now(),
        policy,
        access_review: access_review_report,
        audit_summary,
        retention_summary,
    };

    HttpResponse::Ok().json(bundle)
}