use std::future::{ready, Ready};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use futures_util::future::LocalBoxFuture;
use crate::auth::jwt::decode_jwt;

pub struct JwtAuth;

impl<S, B> Transform<S, ServiceRequest> for JwtAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = JwtAuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(JwtAuthMiddleware { service }))
    }
}

pub struct JwtAuthMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for JwtAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Try Authorization header first
        let auth_header = req.headers().get("Authorization");

        let mut token_opt: Option<String> = None;

        if let Some(auth_str) = auth_header.and_then(|h| h.to_str().ok()) {
            if auth_str.starts_with("Bearer ") {
                token_opt = Some(auth_str[7..].to_string());
            }
        }

        // Fallback: allow `token` query param (useful for browser WebSocket connections)
        if token_opt.is_none() {
            if let Some(q) = req.uri().query() {
                for pair in q.split('&') {
                    if let Some(pos) = pair.find('=') {
                        let (k, v) = pair.split_at(pos);
                        if k == "token" {
                            // v starts with '='
                            token_opt = Some(v[1..].to_string());
                            break;
                        }
                    }
                }
            }
        }

        if let Some(token) = token_opt {
            match decode_jwt(&token) {
                Ok(token_data) => {
                    req.extensions_mut().insert(token_data.claims);
                    let fut = self.service.call(req);
                    return Box::pin(async move {
                        let res = fut.await?;
                        Ok(res)
                    });
                }
                Err(_) => {
                    return Box::pin(ready(Err(actix_web::error::ErrorUnauthorized("Invalid token"))));
                }
            }
        }

        Box::pin(ready(Err(actix_web::error::ErrorUnauthorized("Missing or invalid authorization header"))))
    }
}
