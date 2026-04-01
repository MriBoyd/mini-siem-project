use actix_web::{get, put, web, HttpMessage, HttpRequest, HttpResponse, Responder};

use crate::api::server::AppState;
use crate::api::tenant::enforce_tenant_fixed_window;
use crate::auth::jwt::Claims;
use crate::costs::{build_cost_dashboard, load_tenant_cost_policy, save_tenant_cost_policy};
use crate::db::models::audit::AuditEvent;
use crate::db::models::data_cost::{TenantDataCostPolicy, TenantDataCostPolicyUpdate};
use crate::utils::audit::{audit_payload, hash_audit_payload, sign_audit_hash};
use chrono::Utc;
use uuid::Uuid;

fn require_cost_roles(claims: &Claims) -> bool {
    claims.roles.contains(&"analyst".to_string()) || claims.roles.contains(&"admin".to_string())
}

async fn record_cost_audit(
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
        "data_cost",
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
        resource_type: "data_cost".to_string(),
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

#[get("/cost/policy")]
pub async fn get_cost_policy(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !require_cost_roles(&claims) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "insufficient role"}));
    }

    match load_tenant_cost_policy(&state, &claims.tenant_id).await {
        Ok(policy) => HttpResponse::Ok().json(policy),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to load cost policy: {}", e)})),
    }
}

#[put("/cost/policy")]
pub async fn update_cost_policy(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<TenantDataCostPolicyUpdate>,
) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !require_cost_roles(&claims) {
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

    let mut policy = match load_tenant_cost_policy(&state, &claims.tenant_id).await {
        Ok(policy) => policy,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to load cost policy: {}", e)})),
    };

    if let Some(value) = body.daily_ingest_bytes_budget { policy.daily_ingest_bytes_budget = value; }
    if let Some(value) = body.hot_storage_bytes_budget { policy.hot_storage_bytes_budget = value; }
    if let Some(value) = body.warm_storage_bytes_budget { policy.warm_storage_bytes_budget = value; }
    if let Some(value) = body.cold_storage_bytes_budget { policy.cold_storage_bytes_budget = value; }
    if let Some(value) = body.sampling_enabled { policy.sampling_enabled = value; }
    if let Some(value) = body.low_value_sampling_percent { policy.low_value_sampling_percent = value; }
    if let Some(value) = body.high_value_sampling_percent { policy.high_value_sampling_percent = value; }
    if let Some(value) = body.drop_low_value_when_over_budget { policy.drop_low_value_when_over_budget = value; }
    if let Some(value) = body.schema_drop_rules.clone() { policy.schema_drop_rules = value; }
    if let Some(value) = body.source_budgets.clone() { policy.source_budgets = value; }
    if let Some(value) = body.integration_budgets.clone() { policy.integration_budgets = value; }
    if let Some(value) = body.team_budgets.clone() { policy.team_budgets = value; }

    match save_tenant_cost_policy(&state, &policy).await {
        Ok(saved) => {
            let _ = record_cost_audit(
                &state,
                &claims,
                "data_cost.policy_update",
                Some(&saved.tenant_id),
                serde_json::json!({
                    "daily_ingest_bytes_budget": saved.daily_ingest_bytes_budget,
                    "sampling_enabled": saved.sampling_enabled,
                }),
            ).await;
            HttpResponse::Ok().json(saved)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to save cost policy: {}", e)})),
    }
}

#[get("/cost/dashboard")]
pub async fn get_cost_dashboard(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !require_cost_roles(&claims) {
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

    match build_cost_dashboard(&state, &claims.tenant_id).await {
        Ok(dashboard) => HttpResponse::Ok().json(dashboard),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to build cost dashboard: {}", e)})),
    }
}