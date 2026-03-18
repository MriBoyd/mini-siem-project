use actix_web::{web, HttpResponse, HttpRequest};
use serde::Deserialize;
use anyhow::Result;
use crate::db::PostgresDb;
use crate::auth::jwt::JwtConfig;
use argon2::{Argon2, password_hash::{PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng, PasswordHash}};
use rand::{RngCore};
use chrono::{Utc, Duration};
use base64::Engine;
use sha2::Digest;

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

pub async fn register(db: web::Data<PostgresDb>, req: web::Json<RegisterRequest>) -> actix_web::Result<HttpResponse> {
    // hash password with Argon2
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default().hash_password(req.password.as_bytes(), &salt).map_err(|e| actix_web::error::ErrorInternalServerError(e))?.to_string();

    match db.create_user(&req.email, &password_hash).await {
        Ok(id) => Ok(HttpResponse::Created().json(serde_json::json!({"id": id}))),
        Err(e) => Err(actix_web::error::ErrorInternalServerError(e)),
    }
}

pub async fn login(db: web::Data<PostgresDb>, jwt: web::Data<JwtConfig>, req: web::Json<LoginRequest>) -> actix_web::Result<HttpResponse> {
    // fetch user
    match db.get_user_by_email(&req.email).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))? {
        Some((user_id, password_hash, roles)) => {
            let parsed = PasswordHash::new(&password_hash).map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
            Argon2::default().verify_password(req.password.as_bytes(), &parsed).map_err(|_| actix_web::error::ErrorUnauthorized("invalid credentials"))?;

            // create tokens
            let roles_clone = roles.clone();
            let access = jwt.create_access_token(&user_id.to_string(), roles_clone).map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

            // create refresh token (random 32 bytes base64)
            let mut rng = rand::rngs::OsRng;
            let mut b = [0u8;32]; rng.fill_bytes(&mut b);
            let refresh = base64::engine::general_purpose::STANDARD.encode(&b);
            // store hash of refresh token
            let refresh_hash = sha2::Sha256::digest(&refresh.as_bytes());
            let refresh_hash_b64 = base64::engine::general_purpose::STANDARD.encode(refresh_hash);

            let expires_at = Utc::now() + Duration::days(30);
            db.store_refresh_token(user_id, &refresh_hash_b64, expires_at).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

            Ok(HttpResponse::Ok().json(serde_json::json!({"access_token": access, "refresh_token": refresh, "expires_in": jwt.access_ttl_minutes * 60})))
        }
        None => Err(actix_web::error::ErrorUnauthorized("invalid credentials")),
    }
}

#[derive(Deserialize)]
pub struct RefreshRequest { pub refresh_token: String }

pub async fn refresh(db: web::Data<PostgresDb>, jwt: web::Data<JwtConfig>, req: web::Json<RefreshRequest>) -> actix_web::Result<HttpResponse> {
    // hash incoming token and validate
    let h = sha2::Sha256::digest(req.refresh_token.as_bytes());
    let h_b64 = base64::engine::general_purpose::STANDARD.encode(h);
    if let Some(user_id) = db.validate_refresh_token(&h_b64).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))? {
        // rotate: revoke old and issue new
        db.revoke_refresh_token(&h_b64).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

        let roles = vec!["user".to_string()];
        let access = jwt.create_access_token(&user_id.to_string(), roles.clone()).map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

        let mut rng = rand::rngs::OsRng;
        let mut b = [0u8;32]; rng.fill_bytes(&mut b);
        let refresh = base64::engine::general_purpose::STANDARD.encode(&b);
        let refresh_hash = sha2::Sha256::digest(refresh.as_bytes());
        let refresh_hash_b64 = base64::engine::general_purpose::STANDARD.encode(refresh_hash);
        let expires_at = Utc::now() + Duration::days(30);
        db.store_refresh_token(user_id, &refresh_hash_b64, expires_at).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

        Ok(HttpResponse::Ok().json(serde_json::json!({"access_token": access, "refresh_token": refresh})))
    } else {
        Err(actix_web::error::ErrorUnauthorized("invalid refresh token"))
    }
}

pub async fn logout(db: web::Data<PostgresDb>, req: web::Json<RefreshRequest>) -> actix_web::Result<HttpResponse> {
    let h = sha2::Sha256::digest(req.refresh_token.as_bytes());
    let h_b64 = base64::engine::general_purpose::STANDARD.encode(h);
    db.revoke_refresh_token(&h_b64).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    Ok(HttpResponse::Ok().finish())
}

pub async fn me(req: HttpRequest) -> actix_web::Result<HttpResponse> {
    use crate::auth::jwt::JwtConfig;

    let jwt = req.app_data::<web::Data<JwtConfig>>().cloned().ok_or_else(|| actix_web::error::ErrorInternalServerError("JWT config missing"))?;
    let header = req.headers().get("Authorization").and_then(|h| h.to_str().ok()).ok_or_else(|| actix_web::error::ErrorUnauthorized("missing auth header"))?;
    if !header.starts_with("Bearer ") { return Err(actix_web::error::ErrorUnauthorized("invalid auth header")); }
    let token = header.trim_start_matches("Bearer ").trim();
    let data = jwt.verify_access_token(token).map_err(|_| actix_web::error::ErrorUnauthorized("invalid token"))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"sub": data.claims.sub, "roles": data.claims.roles})))
}
