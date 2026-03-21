use actix_web::{get, web, HttpResponse, Responder, HttpRequest, HttpMessage, Error};
use futures_util::StreamExt;
use tokio::sync::broadcast;
use tracing::{info, warn, error};

use crate::api::server::AppState;
use crate::auth::jwt::Claims;

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

    match state.db.get_recent_alerts(50).await {
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

    let (res, mut session, mut msg_stream) = actix_ws::handle(&req, stream)?;
    let mut alert_rx = state.alert_tx.subscribe();

    info!("🔌 WebSocket connected for alerts: user={}", claims.sub);

    // Spawn a task to manage this WebSocket connection
    actix_rt::spawn(async move {
        loop {
            tokio::select! {
                // Listen for alerts from the broadcast channel
                result = alert_rx.recv() => {
                    match result {
                        Ok(alert) => {
                            let msg = match serde_json::to_string(&alert) {
                                Ok(m) => m,
                                Err(e) => {
                                    error!("Failed to serialize alert: {}", e);
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
