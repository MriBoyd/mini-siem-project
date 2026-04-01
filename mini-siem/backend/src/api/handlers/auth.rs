use actix_web::{post, get, web, HttpResponse, Responder, HttpRequest, HttpMessage};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use tracing::error;

use crate::api::server::AppState;
use crate::api::tenant::enforce_tenant_fixed_window;
use crate::auth::{hash_password, verify_password, create_claims, create_ws_claims, encode_jwt, generate_refresh_token, TokenPair, Claims};
use crate::db::cache::Cache;
use crate::db::models::user::{UserResponse};

#[derive(Deserialize)]
pub struct RegisterRequest {
    #[serde(default)]
    pub tenant_id: String,
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    #[serde(default)]
    pub tenant_id: String,
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    #[serde(default)]
    pub tenant_id: String,
    pub refresh_token: String,
}

fn tenant_or_default(tenant_id: &str) -> &str {
    if tenant_id.is_empty() {
        "default"
    } else {
        tenant_id
    }
}

#[derive(Serialize)]
pub struct WsTokenResponse {
    pub ws_token: String,
    pub expires_in_seconds: u64,
}

#[post("/register")]
pub async fn register(
    state: web::Data<AppState>,
    req: web::Json<RegisterRequest>,
) -> impl Responder {
    let tenant_id = tenant_or_default(&req.tenant_id);

    if req.email.is_empty() || req.password.len() < 8 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid email or password"}));
    }

    let rate_limit_key = format!("rate_limit:register:{}:{}", tenant_id, req.email);
    match state.redis.allow_sliding_window(&rate_limit_key, 60000, 3).await {
        Ok(allowed) if !allowed => return HttpResponse::TooManyRequests().json(serde_json::json!({"error": "Too many registration attempts"})),
        Err(e) => {
            error!("Redis error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Internal server error"}));
        }
        _ => {}
    }

    // Check pre-existence (optional optimization)
    match state.db.get_user_by_email(tenant_id, &req.email).await {
        Ok(Some(_)) => return HttpResponse::Conflict().json(serde_json::json!({"error": "User already exists"})),
        Err(e) => {
            error!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Internal server error"}));
        }
        _ => {}
    }

    let password_hash = match hash_password(&req.password) {
        Ok(h) => h,
        Err(e) => {
            error!("Hashing error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Internal server error"}));
        }
    };

    match state.db.create_user(tenant_id, &req.email, &password_hash, "user").await {
        Ok(user) => HttpResponse::Created().json(UserResponse::from(user)),
        Err(e) => {
            // Check for unique constraint violation
            if e.to_string().contains("constraint") || e.to_string().contains("unique") {
                return HttpResponse::Conflict().json(serde_json::json!({"error": "User already exists"}));
            }
            error!("Database error during user creation: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "Internal server error"}))
        }
    }
}

#[post("/login")]
pub async fn login(
    state: web::Data<AppState>,
    req: web::Json<LoginRequest>,
) -> impl Responder {
    let tenant_id = tenant_or_default(&req.tenant_id);

    let rate_limit_key = format!("rate_limit:login:{}:{}", tenant_id, req.email);
    match state.redis.allow_sliding_window(&rate_limit_key, 60000, 5).await {
        Ok(allowed) if !allowed => return HttpResponse::TooManyRequests().json(serde_json::json!({"error": "Too many login attempts"})),
        Err(e) => {
            error!("Redis error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Internal server error"}));
        }
        _ => {}
    }

    let user = match state.db.get_user_by_email(tenant_id, &req.email).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid credentials"})),
        Err(e) => {
            error!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Internal server error"}));
        }
    };

    match verify_password(&req.password, &user.password_hash) {
        Ok(true) => (),
        _ => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid credentials"})),
    }

    let claims = create_claims(&user.id.to_string(), &user.tenant_id, &user.email, vec![&user.role], 15);
    let access_token = match encode_jwt(&claims) {
        Ok(t) => t,
        Err(e) => {
            error!("JWT error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Internal server error"}));
        }
    };

    let refresh_token = generate_refresh_token();
    
    if let Err(e) = state.redis.store_refresh_token(&user.id.to_string(), &user.tenant_id, &refresh_token, 7 * 24 * 3600).await {
        error!("Redis error storing refresh token: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Internal server error"}));
    }

    HttpResponse::Ok().json(TokenPair {
        access_token,
        refresh_token,
    })
}

#[post("/refresh")]
pub async fn refresh(
    state: web::Data<AppState>,
    req: web::Json<RefreshRequest>,
) -> impl Responder {
    let tenant_id = tenant_or_default(&req.tenant_id);

    let user_id_str = match state.redis.get_user_id_by_refresh_token(&req.refresh_token).await {
        Ok(Some(id)) => id,
        Ok(None) => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid or expired refresh token"})),
        Err(e) => {
            error!("Redis error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Internal server error"}));
        }
    };

    let user_id_part = user_id_str.rsplit_once(':').map(|(_, user_id)| user_id).unwrap_or(&user_id_str);
    let user_id = match Uuid::parse_str(user_id_part) {
        Ok(id) => id,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Internal server error"})),
    };

    let user = match state.db.get_user_by_id(tenant_id, user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::Unauthorized().finish(),
        Err(e) => {
            error!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Internal server error"}));
        }
    };

    // Revoke old token (rotation)
    let _ = state.redis.revoke_refresh_token(&req.refresh_token).await;

    // Generate new pair
    let claims = create_claims(&user.id.to_string(), &user.tenant_id, &user.email, vec![&user.role], 15);
    let access_token = match encode_jwt(&claims) {
        Ok(t) => t,
        Err(e) => {
            error!("JWT error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Internal server error"}));
        }
    };

    let new_refresh_token = generate_refresh_token();
    
    if let Err(e) = state.redis.store_refresh_token(&user.id.to_string(), &user.tenant_id, &new_refresh_token, 7 * 24 * 3600).await {
        error!("Redis error: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Internal server error"}));
    }

    HttpResponse::Ok().json(TokenPair {
        access_token,
        refresh_token: new_refresh_token,
    })
}

#[post("/logout")]
pub async fn logout(
    state: web::Data<AppState>,
    body: web::Json<RefreshRequest>,
) -> impl Responder {
    if let Err(e) = state.redis.revoke_refresh_token(&body.refresh_token).await {
        error!("Redis error: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Internal server error"}));
    }

    HttpResponse::Ok().finish()
}

#[post("/ws-token")]
pub async fn ws_token(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    let claims = {
        let exts = req.extensions();
        match exts.get::<Claims>().cloned() {
            Some(c) => c,
            None => return HttpResponse::Unauthorized().finish(),
        }
    };

    let ws_claims = create_ws_claims(&claims.sub, &claims.tenant_id, &claims.email, claims.roles.iter().map(|s| s.as_str()).collect(), 60);
    let jti = ws_claims.jti.clone().unwrap_or_default();

    if let Err(response) = enforce_tenant_fixed_window(
        &state,
        &claims.tenant_id,
        "ws_connections",
        state.tenant_limits.ws_connections_per_minute,
        1,
    ).await {
        return response;
    }

    let ws_token = match encode_jwt(&ws_claims) {
        Ok(t) => t,
        Err(e) => {
            error!("JWT error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Internal server error"}));
        }
    };

    let token_key = format!("ws_token:{}:{}", claims.tenant_id, jti);
    if let Err(e) = state.redis.set_string(&token_key, &claims.sub, Some(60)).await {
        error!("Redis error storing websocket token: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Internal server error"}));
    }

    HttpResponse::Ok().json(WsTokenResponse {
        ws_token,
        expires_in_seconds: 60,
    })
}

#[get("/me")]
pub async fn me(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    let exts = req.extensions();
    let claims = match exts.get::<Claims>() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().finish(),
    };

    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => return HttpResponse::Unauthorized().finish(),
    };

    match state.db.get_user_by_id(&claims.tenant_id, user_id).await {
        Ok(Some(user)) => HttpResponse::Ok().json(UserResponse::from(user)),
        Ok(None) => HttpResponse::NotFound().finish(),
        Err(e) => {
            error!("Database error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "Internal server error"}))
        }
    }
}
