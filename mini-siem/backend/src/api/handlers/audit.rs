use actix_web::{get, web, HttpRequest, HttpMessage, HttpResponse, Responder};
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use crate::api::server::AppState;
use crate::api::tenant::enforce_tenant_fixed_window;
use crate::auth::jwt::Claims;
use crate::db::models::audit::AuditEvent;
use crate::utils::audit::{audit_payload, hash_audit_payload, sign_audit_hash};

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    pub tenant_id: Option<String>,
    pub limit: Option<i64>,
}

async fn record_audit_view(
    state: &AppState,
    claims: &Claims,
    target_tenant_id: &str,
    limit: i64,
) -> Result<(), HttpResponse> {
    let cross_tenant = target_tenant_id != claims.tenant_id;
    let action = if cross_tenant { "audit.view_cross_tenant" } else { "audit.view" };
    let payload = audit_payload(
        &claims.tenant_id,
        &claims.sub,
        &claims.email,
        &claims.roles,
        action,
        "audit",
        None,
        Some(target_tenant_id),
        claims.jti.as_deref(),
        serde_json::json!({"limit": limit, "cross_tenant": cross_tenant}),
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
        resource_type: "audit".to_string(),
        resource_id: None,
        target_tenant_id: Some(target_tenant_id.to_string()),
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

#[get("/admin/audit")]
pub async fn list_audit_events(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<AuditQuery>,
) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !claims.roles.iter().any(|role| role == "admin") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }

    let target_tenant_id = query.tenant_id.clone().unwrap_or_else(|| claims.tenant_id.clone());
    let limit = query.limit.unwrap_or(100).clamp(1, 500);

    if let Err(response) = enforce_tenant_fixed_window(
        &state,
        &claims.tenant_id,
        "audit_queries",
        state.tenant_limits.audit_queries_per_minute,
        1,
    ).await {
        return response;
    }

    let events = match state.db.list_audit_events(&target_tenant_id, limit).await {
        Ok(events) => events,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to query audit events: {}", e)})),
    };

    if let Err(response) = record_audit_view(&state, &claims, &target_tenant_id, limit).await {
        return response;
    }

    HttpResponse::Ok().json(events)
}