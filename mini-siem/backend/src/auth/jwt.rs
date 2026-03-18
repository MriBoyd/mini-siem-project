use jsonwebtoken::{EncodingKey, DecodingKey, Header, Validation, encode, decode, TokenData};
use serde::{Serialize, Deserialize};
use chrono::{Utc, Duration};
use anyhow::Result;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: i64,
    pub roles: Vec<String>,
}

pub struct JwtConfig {
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
    pub access_ttl_minutes: i64,
}

impl JwtConfig {
    pub fn from_env() -> Result<Self> {
        let priv_pem = std::env::var("JWT_PRIVATE_PEM").expect("JWT_PRIVATE_PEM must be set (PEM RSA private key)");
        let pub_pem = std::env::var("JWT_PUBLIC_PEM").expect("JWT_PUBLIC_PEM must be set (PEM RSA public key)");
        let access_ttl_minutes = std::env::var("JWT_ACCESS_TTL_MINUTES").ok().and_then(|s| s.parse().ok()).unwrap_or(15);

        Ok(Self {
            encoding_key: EncodingKey::from_rsa_pem(priv_pem.as_bytes())?,
            decoding_key: DecodingKey::from_rsa_pem(pub_pem.as_bytes())?,
            access_ttl_minutes,
        })
    }

    pub fn create_access_token(&self, subject: &str, roles: Vec<String>) -> Result<String> {
        let exp = (Utc::now() + Duration::minutes(self.access_ttl_minutes)).timestamp();
        let claims = Claims { sub: subject.to_string(), exp, roles };
        let token = encode(&Header::new(jsonwebtoken::Algorithm::RS256), &claims, &self.encoding_key)?;
        Ok(token)
    }

    pub fn verify_access_token(&self, token: &str) -> Result<TokenData<Claims>> {
        let mut v = Validation::new(jsonwebtoken::Algorithm::RS256);
        v.validate_exp = true;
        let data = decode::<Claims>(token, &self.decoding_key, &v)?;
        Ok(data)
    }
}
