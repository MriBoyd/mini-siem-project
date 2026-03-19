pub mod jwt;

use actix_web::{HttpRequest, HttpResponse, web};
use crate::db::PostgresDb;

// Middleware placeholder for Actix-web
pub struct AuthMiddleware {
    // Implementation would validate JWTs, attach user info to request extensions
}

// Example protected handler signature
pub async fn get_alerts(
    _req: HttpRequest,
    _db: web::Data<PostgresDb>,
    _auth: AuthMiddleware,
) -> HttpResponse {
    HttpResponse::Ok().finish()
}