use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, TokenData, Algorithm};
use anyhow::{Result, Context};
use std::env;
use std::sync::OnceLock;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,    // user_id
    pub tenant_id: String,
    pub email: String,
    pub roles: Vec<String>,
    pub exp: usize,
    pub iat: usize,
}

static ENCODING_KEY: OnceLock<EncodingKey> = OnceLock::new();
static DECODING_KEY: OnceLock<DecodingKey> = OnceLock::new();

fn get_encoding_key() -> Result<&'static EncodingKey> {
    if let Some(key) = ENCODING_KEY.get() {
        return Ok(key);
    }

    let private_key = env::var("JWT_PRIVATE_KEY")
        .context("JWT_PRIVATE_KEY not set")?;

    // Support PEMs stored with escaped newlines in env ("\n"). Replace so the PEM bytes are valid.
    let private_key = private_key.replace("\\n", "\n");

    let key = EncodingKey::from_rsa_pem(private_key.as_bytes())
        .context("Failed to create encoding key")?;
    
    Ok(ENCODING_KEY.get_or_init(|| key))
}

fn get_decoding_key() -> Result<&'static DecodingKey> {
    if let Some(key) = DECODING_KEY.get() {
        return Ok(key);
    }

    let public_key = env::var("JWT_PUBLIC_KEY")
        .context("JWT_PUBLIC_KEY not set")?;

    // Support PEMs stored with escaped newlines in env ("\n").
    let public_key = public_key.replace("\\n", "\n");

    let key = DecodingKey::from_rsa_pem(public_key.as_bytes())
        .context("Failed to create decoding key")?;
    
    Ok(DECODING_KEY.get_or_init(|| key))
}

pub fn create_claims(user_id: &str, tenant_id: &str, email: &str, roles: Vec<&str>, minutes: i64) -> Claims {
    let now = Utc::now();
    let exp = (now + Duration::minutes(minutes)).timestamp() as usize;
    let iat = now.timestamp() as usize;
    
    Claims {
        sub: user_id.to_string(),
        tenant_id: tenant_id.to_string(),
        email: email.to_string(),
        roles: roles.into_iter().map(|s| s.to_string()).collect(),
        exp,
        iat,
    }
}

pub fn encode_jwt(claims: &Claims) -> Result<String> {
    let encoding_key = get_encoding_key()?;
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("JWT".to_string());
    
    encode(&header, claims, encoding_key)
        .context("Failed to encode JWT")
}

pub fn decode_jwt(token: &str) -> Result<TokenData<Claims>> {
    let decoding_key = get_decoding_key()?;
    let validation = Validation::new(Algorithm::RS256);
    
    decode::<Claims>(token, decoding_key, &validation)
        .context("Failed to decode JWT")
}
