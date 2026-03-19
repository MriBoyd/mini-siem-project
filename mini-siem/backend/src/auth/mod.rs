use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,      // user id
    role: UserRole,   // admin, analyst, viewer
    exp: usize,       // expiration
}

#[derive(Debug, Serialize, Deserialize)]
enum UserRole {
    Admin,
    Analyst,
    Viewer,
}

// Middleware for Actix-web
pub struct AuthMiddleware {
    // ...
}

// Add to your API handlers
async fn get_alerts(
    req: HttpRequest,
    db: web::Data<PostgresDb>,
    _: AuthMiddleware,  // This enforces auth
) -> HttpResponse {
    // Only authenticated users reach here
}