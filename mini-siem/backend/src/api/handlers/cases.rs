use actix_web::{get, post, patch, web, HttpMessage, HttpRequest, HttpResponse, Responder};
use chrono::Utc;
use uuid::Uuid;

use crate::api::server::AppState;
use crate::api::tenant::enforce_tenant_fixed_window;
use crate::auth::jwt::Claims;
use crate::db::models::audit::AuditEvent;
use crate::db::models::case::{AddCaseEventRequest, CaseStatus, CreateCaseRequest, RunPlaybookRequest, UpdateCaseRequest};
use crate::utils::audit::{audit_payload, hash_audit_payload, sign_audit_hash};

async fn record_case_audit(
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
        "case",
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
        resource_type: "case".to_string(),
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

fn require_case_roles(claims: &Claims) -> bool {
    claims.roles.contains(&"analyst".to_string()) || claims.roles.contains(&"admin".to_string())
}

#[get("/cases")]
pub async fn list_cases(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !require_case_roles(&claims) {
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

    match state.db.list_cases(&claims.tenant_id).await {
        Ok(cases) => HttpResponse::Ok().json(cases),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to list cases: {}", e)})),
    }
}

#[get("/cases/{case_id}")]
pub async fn get_case(req: HttpRequest, state: web::Data<AppState>, case_id: web::Path<Uuid>) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !require_case_roles(&claims) {
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

    match state.db.get_case_detail(&claims.tenant_id, case_id.into_inner()).await {
        Ok(Some(case)) => HttpResponse::Ok().json(case),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "case not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to load case: {}", e)})),
    }
}

#[post("/cases")]
pub async fn create_case(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<CreateCaseRequest>,
) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !require_case_roles(&claims) {
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

    let alert = match state.db.get_alert(&claims.tenant_id, body.alert_id).await {
        Ok(Some(alert)) => alert,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "alert not found"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to load alert: {}", e)})),
    };

    match state.db.create_case_from_alert(
        &alert,
        body.owner_user_id.as_deref(),
        body.owner_email.as_deref(),
        body.title.clone(),
        body.summary.clone(),
        None,
    ).await {
        Ok(case) => {
            let _ = record_case_audit(
                &state,
                &claims,
                "case.create",
                Some(&case.id.to_string()),
                serde_json::json!({"alert_id": alert.id, "severity": alert.severity.to_string()}),
            ).await;
            HttpResponse::Created().json(case)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to create case: {}", e)})),
    }
}

#[patch("/cases/{case_id}")]
pub async fn update_case(
    req: HttpRequest,
    state: web::Data<AppState>,
    case_id: web::Path<Uuid>,
    body: web::Json<UpdateCaseRequest>,
) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !require_case_roles(&claims) {
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

    let status = body.status.clone();
    match state.db.update_case(
        &claims.tenant_id,
        case_id.into_inner(),
        status,
        Some(body.owner_user_id.clone()),
        Some(body.owner_email.clone()),
        Some(body.outcome.clone()),
        Some(body.postmortem_summary.clone()),
    ).await {
        Ok(case) => {
            let _ = record_case_audit(
                &state,
                &claims,
                "case.update",
                Some(&case.id.to_string()),
                serde_json::json!({
                    "status": case.status,
                    "owner_user_id": case.owner_user_id,
                    "owner_email": case.owner_email,
                    "outcome": case.outcome,
                }),
            ).await;
            HttpResponse::Ok().json(case)
        }
        Err(e) if e.to_string().contains("case not found") => HttpResponse::NotFound().json(serde_json::json!({"error": "case not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to update case: {}", e)})),
    }
}

#[post("/cases/{case_id}/timeline")]
pub async fn add_timeline_event(
    req: HttpRequest,
    state: web::Data<AppState>,
    case_id: web::Path<Uuid>,
    body: web::Json<AddCaseEventRequest>,
) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !require_case_roles(&claims) {
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

    let event_type = body.event_type.trim();
    if event_type.is_empty() || body.message.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "event_type and message are required"}));
    }

    let case = match state.db.get_case_by_id(&claims.tenant_id, case_id.into_inner()).await {
        Ok(Some(case)) => case,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "case not found"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to load case: {}", e)})),
    };

    if let Err(e) = state.db.record_case_event(
        &claims.tenant_id,
        case.id,
        event_type,
        &body.message,
        Some(&claims.sub),
        Some(&claims.email),
        body.metadata.clone().unwrap_or_else(|| serde_json::json!({})),
    ).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to add timeline event: {}", e)}));
    }

    let _ = record_case_audit(
        &state,
        &claims,
        "case.timeline_event",
        Some(&case.id.to_string()),
        serde_json::json!({"event_type": event_type, "message": body.message}),
    ).await;

    HttpResponse::Created().json(serde_json::json!({"status": "ok"}))
}

#[post("/cases/{case_id}/playbook/run")]
pub async fn run_playbook(
    req: HttpRequest,
    state: web::Data<AppState>,
    case_id: web::Path<Uuid>,
    body: web::Json<RunPlaybookRequest>,
) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !require_case_roles(&claims) {
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

    let case = match state.db.get_case_by_id(&claims.tenant_id, case_id.into_inner()).await {
        Ok(Some(case)) => case,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "case not found"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to load case: {}", e)})),
    };

    let playbook = match body.playbook_id.or(case.playbook_id) {
        Some(playbook_id) => match state.db.get_case_playbook(&claims.tenant_id, playbook_id).await {
            Ok(Some(playbook)) => playbook,
            Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "playbook not found"})),
            Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to load playbook: {}", e)})),
        },
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "case has no playbook"})),
    };

    let _ = state.db.update_case(
        &claims.tenant_id,
        case.id,
        Some(CaseStatus::Investigating),
        None,
        None,
        None,
        None,
    ).await;

    let _ = state.db.record_case_event(
        &claims.tenant_id,
        case.id,
        "playbook.started",
        &format!("Playbook '{}' started", playbook.name),
        Some(&claims.sub),
        Some(&claims.email),
        serde_json::json!({"playbook_id": playbook.id, "playbook_name": playbook.name}),
    ).await;

    if let Some(steps) = playbook.steps.as_array() {
        for step in steps {
            let title = step.get("title").and_then(|value| value.as_str()).unwrap_or("Unnamed step");
            let action_type = step.get("action_type").and_then(|value| value.as_str()).unwrap_or("manual");
            let description = step.get("description").and_then(|value| value.as_str()).unwrap_or(title);
            let automated = step.get("automated").and_then(|value| value.as_bool()).unwrap_or(false);

            let _ = state.db.record_case_event(
                &claims.tenant_id,
                case.id,
                if automated { "playbook.step.automated" } else { "playbook.step.manual" },
                title,
                Some(&claims.sub),
                Some(&claims.email),
                serde_json::json!({
                    "title": title,
                    "action_type": action_type,
                    "description": description,
                    "automated": automated,
                }),
            ).await;
        }
    }

    let _ = record_case_audit(
        &state,
        &claims,
        "case.playbook_run",
        Some(&case.id.to_string()),
        serde_json::json!({"playbook_id": playbook.id, "playbook_name": playbook.name}),
    ).await;

    HttpResponse::Ok().json(serde_json::json!({"status": "ok", "playbook": playbook.name}))
}

#[get("/case-playbooks")]
pub async fn list_playbooks(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    if !require_case_roles(&claims) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "insufficient role"}));
    }

    match state.db.list_case_playbooks(&claims.tenant_id).await {
        Ok(playbooks) => HttpResponse::Ok().json(playbooks),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to list playbooks: {}", e)})),
    }
}