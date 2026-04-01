use actix_web::{get, web, HttpResponse, Responder, HttpRequest, HttpMessage, Error};
use futures_util::StreamExt;
use tokio::sync::broadcast;
use tracing::{info, warn, error};

use crate::api::server::AppState;
use crate::auth::jwt::Claims;
use crate::db::cache::Cache;

#[get("/alerts")]
pub async fn list_alerts(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    // RBAC: only users with 'analyst' or 'admin' roles may view alerts
    let exts = req.extensions();
    let claims = match exts.get::<Claims>() {
        Some(c) => c,
        None => return actix_web::error::ErrorUnauthorized("missing auth").error_response(),
    };

    let roles = &claims.roles;
    if !(roles.contains(&"analyst".to_string()) || roles.contains(&"admin".to_string())) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error":"insufficient role"}));
    }

    match state.db.get_recent_alerts(&claims.tenant_id, 50).await {
        Ok(alerts) => HttpResponse::Ok().json(alerts),
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("failed to query alerts: {}", e),
            }))
        }
    }
}

/// WebSocket handler for real-time alerts
pub async fn ws_alerts(
    req: HttpRequest,
    stream: web::Payload,
    state: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    // RBAC check (middleware already verified JWT, but we check roles here)
    let claims = {
        let exts = req.extensions();
        match exts.get::<Claims>().cloned() {
            Some(c) => c,
            None => return Err(actix_web::error::ErrorUnauthorized("missing auth")),
        }
    };

    let roles = &claims.roles;
    if !(roles.contains(&"analyst".to_string()) || roles.contains(&"admin".to_string())) {
        return Err(actix_web::error::ErrorForbidden("insufficient role"));
    }

    if claims.token_use.as_deref() == Some("ws") {
        let jti = match claims.jti.as_deref() {
            Some(jti) => jti,
            None => return Err(actix_web::error::ErrorUnauthorized("missing websocket token id")),
        };
        let token_key = format!("ws_token:{}:{}", claims.tenant_id, jti);
        let token_value = match state.redis.get_string(&token_key).await {
            Ok(Some(value)) => value,
            _ => return Err(actix_web::error::ErrorUnauthorized("expired or invalid websocket token")),
        };
        if token_value != claims.sub {
            return Err(actix_web::error::ErrorUnauthorized("invalid websocket token"));
        }
        if let Err(e) = state.redis.delete_key(&token_key).await {
            error!("Failed to consume websocket token: {}", e);
            return Err(actix_web::error::ErrorUnauthorized("expired or invalid websocket token"));
        }
    }

    let (res, mut session, mut msg_stream) = actix_ws::handle(&req, stream)?;
    let mut alert_rx = state.alert_tx.subscribe();
    let mut stats_rx = state.stats_tx.subscribe();

    info!("🔌 WebSocket connected for alerts: user={}", claims.sub);

    // Spawn a task to manage this WebSocket connection
    actix_rt::spawn(async move {
        loop {
            tokio::select! {
                // Listen for alerts from the broadcast channel
                result = alert_rx.recv() => {
                    match result {
                        Ok(alert) => {
                            if alert.tenant_id != claims.tenant_id {
                                continue;
                            }
                            // send typed alert message
                            let payload = serde_json::json!({"type":"alert","data":alert});
                            let msg = match serde_json::to_string(&payload) {
                                Ok(m) => m,
                                Err(e) => {
                                    error!("Failed to serialize alert payload: {}", e);
                                    continue;
                                }
                            };
                            if session.text(msg).await.is_err() {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("WS client lagged behind {} alerts", n);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
                // Listen for stats updates from the broadcast channel
                result_stats = stats_rx.recv() => {
                    match result_stats {
                        Ok(stats) => {
                            if stats.tenant_id != claims.tenant_id {
                                continue;
                            }
                            let payload = serde_json::json!({"type":"stats","data":stats});
                            let msg = match serde_json::to_string(&payload) {
                                Ok(m) => m,
                                Err(e) => {
                                    error!("Failed to serialize stats payload: {}", e);
                                    continue;
                                }
                            };
                            if session.text(msg).await.is_err() {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("WS client lagged behind {} stats messages", n);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
                // Handle incoming messages from the client (pings, close, etc.)
                msg_opt = msg_stream.next() => {
                    match msg_opt {
                        Some(Ok(actix_ws::Message::Ping(bytes))) => {
                            if session.pong(&bytes).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(actix_ws::Message::Text(text))) => {
                            info!("Received WS message from {}: {}", claims.sub, text);
                        }
                        Some(Ok(actix_ws::Message::Close(reason))) => {
                            info!("WS connection closed: {:?}", reason);
                            let _ = session.close(reason).await;
                            break;
                        }
                        Some(Err(e)) => {
                            error!("WS stream error: {}", e);
                            break;
                        }
                        None => break,
                        _ => {}
                    }
                }
                else => break,
            }
        }
        info!("🔌 WebSocket disconnected: user={}", claims.sub);
    });

    Ok(res)
}
