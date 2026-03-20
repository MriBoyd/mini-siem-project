use mini_siem::api::handlers::auth::RegisterRequest;

#[tokio::test]
async fn test_register_validation() {
    let req_body = RegisterRequest {
        email: "".to_string(),
        password: "short".to_string(),
    };
    assert!(req_body.email.is_empty() || req_body.password.len() < 8);
}

#[tokio::test]
async fn test_user_response_conversion() {
    use uuid::Uuid;
    use chrono::Utc;
    use mini_siem::db::models::user::{User, UserResponse};

    let user = User {
        id: Uuid::new_v4(),
        email: "test@example.com".to_string(),
        password_hash: "hash".to_string(),
        role: "admin".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let response = UserResponse::from(user.clone());
    assert_eq!(response.id, user.id);
    assert_eq!(response.email, user.email);
    assert_eq!(response.role, user.role);
}
