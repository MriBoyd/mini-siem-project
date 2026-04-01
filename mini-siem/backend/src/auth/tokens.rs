use serde::{Deserialize, Serialize};
use rand::{thread_rng, Rng};
use base64::{Engine as _, engine::general_purpose};
use anyhow::{Result, Context};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::env;

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

pub fn generate_refresh_token() -> String {
    let mut rng = thread_rng();
    let token: [u8; 32] = rng.gen();
    general_purpose::STANDARD.encode(token)
}

fn refresh_token_hash_secret() -> Result<Vec<u8>> {
    let secret = env::var("REFRESH_TOKEN_HMAC_SECRET")
        .or_else(|_| env::var("JWT_REFRESH_TOKEN_SECRET"))
        .or_else(|_| env::var("JWT_PRIVATE_KEY"))
        .context("REFRESH_TOKEN_HMAC_SECRET not set")?;

    Ok(secret.replace("\\n", "\n").into_bytes())
}

pub fn hash_refresh_token(token: &str) -> Result<String> {
    let secret = refresh_token_hash_secret()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&secret)
        .context("Failed to initialize refresh token HMAC")?;
    mac.update(token.as_bytes());
    let digest = mac.finalize().into_bytes();
    Ok(general_purpose::URL_SAFE_NO_PAD.encode(digest))
}
