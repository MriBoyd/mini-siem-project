use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, TokenData, errors::Error};
use anyhow::Result;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub roles: Vec<String>,
    pub exp: usize,
}

pub fn create_claims(subject: &str, roles: Vec<&str>, minutes: i64) -> Claims {
    let exp = (Utc::now() + Duration::minutes(minutes)).timestamp() as usize;
    Claims { sub: subject.to_string(), roles: roles.into_iter().map(|s| s.to_string()).collect(), exp }
}

pub fn encode_jwt(claims: &Claims, secret: &str) -> Result<String, Error> {
    encode(&Header::default(), claims, &EncodingKey::from_secret(secret.as_ref()))
}

pub fn decode_jwt(token: &str, secret: &str) -> Result<TokenData<Claims>, Error> {
    decode::<Claims>(token, &DecodingKey::from_secret(secret.as_ref()), &Validation::default())
}
