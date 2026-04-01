use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub fn hash_audit_payload(previous_hash: Option<&str>, payload: &Value) -> Result<String> {
    let mut hasher = Sha256::new();
    if let Some(previous_hash) = previous_hash {
        hasher.update(previous_hash.as_bytes());
    }
    hasher.update(serde_json::to_vec(payload)?);
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn sign_audit_hash(signing_key: &str, event_hash: &str) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(signing_key.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid audit signing key"))?;
    mac.update(event_hash.as_bytes());
    Ok(STANDARD.encode(mac.finalize().into_bytes()))
}

pub fn audit_payload(
    tenant_id: &str,
    actor_user_id: &str,
    actor_email: &str,
    actor_roles: &[String],
    action: &str,
    resource_type: &str,
    resource_id: Option<&str>,
    target_tenant_id: Option<&str>,
    request_id: Option<&str>,
    metadata: Value,
) -> Value {
    serde_json::json!({
        "tenant_id": tenant_id,
        "actor_user_id": actor_user_id,
        "actor_email": actor_email,
        "actor_roles": actor_roles,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "target_tenant_id": target_tenant_id,
        "request_id": request_id,
        "metadata": metadata,
    })
}