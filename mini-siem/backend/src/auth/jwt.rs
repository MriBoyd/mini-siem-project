use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, TokenData, Algorithm};
use anyhow::{Result, anyhow};
use std::env;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,    // user_id
    pub email: String,
    pub roles: Vec<String>,
    pub exp: usize,
    pub iat: usize,
}

pub fn create_claims(user_id: &str, email: &str, roles: Vec<&str>, minutes: i64) -> Claims {
    let now = Utc::now();
    let exp = (now + Duration::minutes(minutes)).timestamp() as usize;
    let iat = now.timestamp() as usize;
    
    Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        roles: roles.into_iter().map(|s| s.to_string()).collect(),
        exp,
        iat,
    }
}

pub fn encode_jwt(claims: &Claims) -> Result<String> {
    let private_key = env::var("JWT_PRIVATE_KEY")
        .map_err(|_| anyhow!("JWT_PRIVATE_KEY not set"))?;
    
    let encoding_key = EncodingKey::from_rsa_pem(private_key.as_bytes())
        .map_err(|e| anyhow!("Failed to create encoding key: {}", e))?;
    
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("JWT".to_string());
    
    encode(&header, claims, &encoding_key)
        .map_err(|e| anyhow!("Failed to encode JWT: {}", e))
}

pub fn decode_jwt(token: &str) -> Result<TokenData<Claims>> {
    let public_key = env::var("JWT_PUBLIC_KEY")
        .map_err(|_| anyhow!("JWT_PUBLIC_KEY not set"))?;
    
    let decoding_key = DecodingKey::from_rsa_pem(public_key.as_bytes())
        .map_err(|e| anyhow!("Failed to create decoding key: {}", e))?;
    
    let validation = Validation::new(Algorithm::RS256);
    
    decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|e| anyhow!("Failed to decode JWT: {}", e))
}
