use actix_web::HttpResponse;

use crate::api::server::AppState;
use crate::db::cache::Cache;

pub async fn enforce_tenant_fixed_window(
    state: &AppState,
    tenant_id: &str,
    resource: &str,
    limit: usize,
    cost: usize,
) -> Result<(), HttpResponse> {
    let quota_key = format!("siem:tenant:{}:quota:{}", tenant_id, resource);
    match state
        .redis
        .allow_fixed_window(&quota_key, 60, limit as u32, cost as u32)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(HttpResponse::TooManyRequests().json(serde_json::json!({
            "error": "tenant quota exceeded",
            "resource": resource,
        }))),
        Err(e) => Err(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("quota check failed: {}", e),
        }))),
    }
}