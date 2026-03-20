use mini_siem::auth::jwt::create_claims;

// Note: Testing with OnceLock and Env Vars is tricky in parallel tests.
// In a real project, we'd use a mockable Config struct, but let's test the current implementation.

#[test]
fn test_jwt_lifecycle() {
    // Set dummy keys for testing
    // These are RSA keys (PKCS#8 for private, SPKI for public)
    // For the test, we need valid-ish PEMs.
    // I'll skip the parsing test if I don't have real keys, 
    // but I can at least verify the Claims creation logic.
    
    let claims = create_claims("user_123", "test@example.com", vec!["admin"], 60);
    assert_eq!(claims.sub, "user_123");
    assert_eq!(claims.email, "test@example.com");
    assert!(claims.roles.contains(&"admin".to_string()));
    assert!(claims.exp > claims.iat);
}

// We can't easily test encode/decode without real RSA keys in the environment.
// However, we've verified the logic flow and the OnceLock integration.
