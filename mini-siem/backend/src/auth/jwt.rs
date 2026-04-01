use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};
use jsonwebtoken::{encode, decode, decode_header, Header, Validation, EncodingKey, DecodingKey, TokenData, Algorithm};
use anyhow::{Result, Context, bail};
use std::env;
use std::{collections::{HashMap, HashSet}, sync::{Mutex, OnceLock}, time::{Duration as StdDuration, Instant}};
use uuid::Uuid;
use tracing::{info, warn};

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    n: Option<String>,
    e: Option<String>,
}

struct CachedJwks {
    expires_at: Instant,
    stale_until: Instant,
    keys: HashMap<String, DecodingKey>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,    // user_id
    pub tenant_id: String,
    pub email: String,
    pub roles: Vec<String>,
    pub iss: String,
    pub aud: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_use: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    pub exp: usize,
    pub iat: usize,
}

static ENCODING_KEY: OnceLock<EncodingKey> = OnceLock::new();
static DECODING_KEY: OnceLock<DecodingKey> = OnceLock::new();
static JWKS_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
static JWKS_CACHE: OnceLock<Mutex<Option<CachedJwks>>> = OnceLock::new();

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

fn get_expected_issuer() -> String {
    env::var("JWT_ISSUER").unwrap_or_else(|_| "mini-siem".to_string())
}

fn get_expected_audience() -> String {
    env::var("JWT_AUDIENCE").unwrap_or_else(|_| "mini-siem-api".to_string())
}

fn jwks_cache_ttl() -> StdDuration {
    let ttl_seconds = env::var("JWT_JWKS_TTL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(300);
    StdDuration::from_secs(ttl_seconds)
}

fn jwks_stale_ttl() -> StdDuration {
    let ttl_seconds = env::var("JWT_JWKS_STALE_TTL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(600);
    StdDuration::from_secs(ttl_seconds)
}

fn jwks_timeout() -> StdDuration {
    let timeout_ms = env::var("JWT_JWKS_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(3000);
    StdDuration::from_millis(timeout_ms)
}

fn get_jwks_client() -> Result<&'static reqwest::Client> {
    if let Some(client) = JWKS_CLIENT.get() {
        return Ok(client);
    }

    let client = reqwest::Client::builder()
        .timeout(jwks_timeout())
        .build()
        .context("Failed to build JWKS HTTP client")?;

    Ok(JWKS_CLIENT.get_or_init(|| client))
}

async fn fetch_jwks(jwks_url: &str) -> Result<CachedJwks> {
    let jwks: Jwks = get_jwks_client()?
        .get(jwks_url)
        .send()
        .await
        .with_context(|| format!("Failed to fetch JWKS from {}", jwks_url))?
        .json()
        .await
        .context("Failed to parse JWKS response")?;

    let mut keys = HashMap::new();
    for jwk in jwks.keys {
        if jwk.kty.as_str() != "RSA" {
            continue;
        }

        let Some(kid) = jwk.kid else {
            continue;
        };

        let n = jwk.n.ok_or_else(|| anyhow::anyhow!("JWKS key missing modulus"))?;
        let e = jwk.e.ok_or_else(|| anyhow::anyhow!("JWKS key missing exponent"))?;
        let key = DecodingKey::from_rsa_components(&n, &e)
            .context("Failed to build decoding key from JWKS")?;
        keys.insert(kid, key);
    }

    Ok(CachedJwks {
        expires_at: Instant::now() + jwks_cache_ttl(),
        stale_until: Instant::now() + jwks_cache_ttl() + jwks_stale_ttl(),
        keys,
    })
}

async fn get_decoding_key_for_kid(kid: Option<&str>) -> Result<DecodingKey> {
    if let Ok(jwks_url) = env::var("JWT_JWKS_URL") {
        let kid = kid.ok_or_else(|| anyhow::anyhow!("JWT header missing kid"))?;
        let cache = JWKS_CACHE.get_or_init(|| Mutex::new(None));

        if let Some(key) = {
            let guard = cache.lock().expect("JWKS cache mutex poisoned");
            guard.as_ref().and_then(|cached| {
                if cached.expires_at > Instant::now() || cached.stale_until > Instant::now() {
                    cached.keys.get(kid).cloned()
                } else {
                    None
                }
            })
        } {
            return Ok(key);
        }

        let fetched = match fetch_jwks(&jwks_url).await {
            Ok(jwks) => jwks,
            Err(fetch_error) => {
                let guard = cache.lock().expect("JWKS cache mutex poisoned");
                if let Some(cached) = guard.as_ref() {
                    if cached.stale_until > Instant::now() {
                        if let Some(key) = cached.keys.get(kid).cloned() {
                            return Ok(key);
                        }
                    }
                }

                return Err(fetch_error);
            }
        };
        let key = fetched
            .keys
            .get(kid)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No JWKS key found for kid {}", kid))?;

        let mut guard = cache.lock().expect("JWKS cache mutex poisoned");
        *guard = Some(fetched);
        return Ok(key);
    }

    Ok(get_decoding_key()?.clone())
}

pub fn spawn_jwks_refresh_task() -> Option<tokio::task::JoinHandle<()>> {
    let jwks_url = env::var("JWT_JWKS_URL").ok()?;
    let refresh_every = jwks_cache_ttl();

    Some(tokio::spawn(async move {
        let mut interval = tokio::time::interval(refresh_every);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            interval.tick().await;

            match fetch_jwks(&jwks_url).await {
                Ok(fetched) => {
                    let mut guard = JWKS_CACHE.get_or_init(|| Mutex::new(None)).lock().expect("JWKS cache mutex poisoned");
                    *guard = Some(fetched);
                    info!("Refreshed JWKS cache successfully");
                }
                Err(err) => {
                    warn!("Failed to refresh JWKS cache: {}", err);
                }
            }
        }
    }))
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
        iss: get_expected_issuer(),
        aud: get_expected_audience(),
        token_use: None,
        jti: None,
        exp,
        iat,
    }
}

pub fn create_ws_claims(user_id: &str, tenant_id: &str, email: &str, roles: Vec<&str>, seconds: i64) -> Claims {
    let now = Utc::now();
    let exp = (now + Duration::seconds(seconds)).timestamp() as usize;
    let iat = now.timestamp() as usize;

    Claims {
        sub: user_id.to_string(),
        tenant_id: tenant_id.to_string(),
        email: email.to_string(),
        roles: roles.into_iter().map(|s| s.to_string()).collect(),
        iss: get_expected_issuer(),
        aud: get_expected_audience(),
        token_use: Some("ws".to_string()),
        jti: Some(Uuid::new_v4().to_string()),
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

pub async fn decode_jwt(token: &str) -> Result<TokenData<Claims>> {
    let header = decode_header(token).context("Failed to parse JWT header")?;
    if header.alg != Algorithm::RS256 {
        bail!("Unsupported JWT algorithm: {:?}", header.alg);
    }

    let decoding_key = get_decoding_key_for_kid(header.kid.as_deref()).await?;
    let mut validation = Validation::new(Algorithm::RS256);
    let issuer = get_expected_issuer();
    let audience = get_expected_audience();
    validation.set_issuer(&[issuer.as_str()]);
    validation.set_audience(&[audience.as_str()]);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.required_spec_claims = HashSet::from([
        "exp".to_string(),
        "iat".to_string(),
        "iss".to_string(),
        "aud".to_string(),
        "sub".to_string(),
    ]);

    decode::<Claims>(token, &decoding_key, &validation)
        .context("Failed to decode JWT")
}
