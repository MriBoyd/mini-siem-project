use std::{future::{ready, Ready}, rc::Rc};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use futures_util::future::LocalBoxFuture;
use crate::auth::jwt::decode_jwt;

pub struct JwtAuth;

impl<S, B> Transform<S, ServiceRequest> for JwtAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = JwtAuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(JwtAuthMiddleware { service: Rc::new(service) }))
    }
}

pub struct JwtAuthMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for JwtAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let mut token_opt: Option<String> = None;

        if let Some(auth_str) = req.headers().get("Authorization").and_then(|h| h.to_str().ok()) {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                token_opt = Some(token.to_string());
            }
        }

        if token_opt.is_none() {
            if let Some(ws_token) = req.headers().get("X-WS-Token").and_then(|h| h.to_str().ok()) {
                token_opt = Some(ws_token.to_string());
            }
        }

        if token_opt.is_none() {
            if let Some(protocols) = req.headers().get("Sec-WebSocket-Protocol").and_then(|h| h.to_str().ok()) {
                for proto in protocols.split(',').map(|p| p.trim()) {
                    if let Some(token) = proto.strip_prefix("ws-token.") {
                        token_opt = Some(token.to_string());
                        break;
                    }
                }
            }
        }

        if let Some(token) = token_opt {
            return Box::pin(async move {
                match decode_jwt(&token).await {
                    Ok(token_data) => {
                        req.extensions_mut().insert(token_data.claims);
                        let fut = service.call(req);
                        let res = fut.await?;
                        Ok(res)
                    }
                    Err(_) => Err(actix_web::error::ErrorUnauthorized("Invalid token")),
                }
            });
        }

        Box::pin(ready(Err(actix_web::error::ErrorUnauthorized("Missing or invalid token"))))
    }
}
