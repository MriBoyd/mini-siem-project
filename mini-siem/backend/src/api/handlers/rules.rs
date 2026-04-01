use actix_web::{delete, get, post, put, web, HttpMessage, HttpRequest, HttpResponse, Responder};
use chrono::Utc;
use uuid::Uuid;

use crate::api::server::AppState;
use crate::api::tenant::enforce_tenant_fixed_window;
use crate::auth::jwt::Claims;
use crate::db::models::audit::AuditEvent;
use crate::db::models::rule::{RuleCreate, RuleUpdate};
use crate::utils::audit::{audit_payload, hash_audit_payload, sign_audit_hash};

async fn record_rule_audit(
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
        "rule",
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
        resource_type: "rule".to_string(),
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

#[get("/rules")]
pub async fn list_rules(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    let claims = {
        let exts = req.extensions();
        match exts.get::<Claims>().cloned() {
            Some(c) => c,
            None => return HttpResponse::Unauthorized().finish(),
        }
    };

    if let Err(response) = enforce_tenant_fixed_window(
        &state,
        &claims.tenant_id,
        "api_requests",
        state.tenant_limits.api_requests_per_minute,
        1,
    ).await {
        return response;
    }

    match state.db.get_all_rules(&claims.tenant_id).await {
        Ok(rules) => HttpResponse::Ok().json(rules),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Database error: {}", e)})),
    }
}

#[post("/rules")]
pub async fn create_rule(
    http_req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<RuleCreate>,
) -> impl Responder {
    let claims = {
        let exts = http_req.extensions();
        match exts.get::<Claims>().cloned() {
            Some(c) => c,
            None => return HttpResponse::Unauthorized().finish(),
        }
    };

    if let Err(response) = enforce_tenant_fixed_window(
        &state,
        &claims.tenant_id,
        "rule_mutations",
        state.tenant_limits.rule_mutations_per_minute,
        1,
    ).await {
        return response;
    }

    let mut rule = body.into_inner();
    rule.tenant_id = claims.tenant_id.clone();

    match state.db.create_rule(&rule).await {
        Ok(rule) => {
            if let Err(response) = record_rule_audit(
                &state,
                &claims,
                "rule.create",
                Some(&rule.id.to_string()),
                serde_json::json!({"name": &rule.name, "rule_type": &rule.rule_type, "severity": &rule.severity}),
            ).await {
                return response;
            }

            HttpResponse::Created().json(rule)
        },
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Database error: {}", e)})),
    }
}

#[get("/rules/{id}")]
pub async fn get_rule(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> impl Responder {
    let claims = {
        let exts = req.extensions();
        match exts.get::<Claims>().cloned() {
            Some(c) => c,
            None => return HttpResponse::Unauthorized().finish(),
        }
    };

    if let Err(response) = enforce_tenant_fixed_window(
        &state,
        &claims.tenant_id,
        "api_requests",
        state.tenant_limits.api_requests_per_minute,
        1,
    ).await {
        return response;
    }

    let id = path.into_inner();
    match state.db.get_rule_by_id(&claims.tenant_id, id).await {
        Ok(Some(rule)) => HttpResponse::Ok().json(rule),
        Ok(None) => HttpResponse::NotFound().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Database error: {}", e)})),
    }
}

#[put("/rules/{id}")]
pub async fn update_rule(
    http_req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
    body: web::Json<RuleUpdate>,
) -> impl Responder {
    let claims = {
        let exts = http_req.extensions();
        match exts.get::<Claims>().cloned() {
            Some(c) => c,
            None => return HttpResponse::Unauthorized().finish(),
        }
    };

    if let Err(response) = enforce_tenant_fixed_window(
        &state,
        &claims.tenant_id,
        "rule_mutations",
        state.tenant_limits.rule_mutations_per_minute,
        1,
    ).await {
        return response;
    }

    let id = path.into_inner();
    match state.db.update_rule(&claims.tenant_id, id, body.into_inner()).await {
        Ok(rule) => {
            if let Err(response) = record_rule_audit(
                &state,
                &claims,
                "rule.update",
                Some(&rule.id.to_string()),
                serde_json::json!({"name": &rule.name, "severity": &rule.severity, "enabled": rule.is_enabled}),
            ).await {
                return response;
            }

            HttpResponse::Ok().json(rule)
        },
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Database error: {}", e)})),
    }
}

#[delete("/rules/{id}")]
pub async fn delete_rule(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> impl Responder {
    let claims = {
        let exts = req.extensions();
        match exts.get::<Claims>().cloned() {
            Some(c) => c,
            None => return HttpResponse::Unauthorized().finish(),
        }
    };

    if let Err(response) = enforce_tenant_fixed_window(
        &state,
        &claims.tenant_id,
        "rule_mutations",
        state.tenant_limits.rule_mutations_per_minute,
        1,
    ).await {
        return response;
    }

    let id = path.into_inner();
    match state.db.delete_rule(&claims.tenant_id, id).await {
        Ok(_) => {
            if let Err(response) = record_rule_audit(
                &state,
                &claims,
                "rule.delete",
                Some(&id.to_string()),
                serde_json::json!({"deleted": true}),
            ).await {
                return response;
            }

            HttpResponse::NoContent().finish()
        },
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Database error: {}", e)})),
    }
}

#[post("/rules/{id}/toggle")]
pub async fn toggle_rule(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> impl Responder {
    let claims = {
        let exts = req.extensions();
        match exts.get::<Claims>().cloned() {
            Some(c) => c,
            None => return HttpResponse::Unauthorized().finish(),
        }
    };

    if let Err(response) = enforce_tenant_fixed_window(
        &state,
        &claims.tenant_id,
        "rule_mutations",
        state.tenant_limits.rule_mutations_per_minute,
        1,
    ).await {
        return response;
    }

    let id = path.into_inner();
    match state.db.get_rule_by_id(&claims.tenant_id, id).await {
        Ok(Some(rule)) => {
            let update = RuleUpdate {
                name: None,
                description: None,
                severity: None,
                threshold: None,
                window_seconds: None,
                condition: None,
                is_enabled: Some(!rule.is_enabled),
            };
            match state.db.update_rule(&claims.tenant_id, id, update).await {
                Ok(updated) => {
                    if let Err(response) = record_rule_audit(
                        &state,
                        &claims,
                        "rule.toggle",
                        Some(&updated.id.to_string()),
                        serde_json::json!({"enabled": updated.is_enabled}),
                    ).await {
                        return response;
                    }

                    HttpResponse::Ok().json(updated)
                },
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Database error: {}", e)})),
            }
        },
        Ok(None) => HttpResponse::NotFound().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Database error: {}", e)})),
    }
}
