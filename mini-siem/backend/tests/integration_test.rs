#[tokio::test]
async fn test_brute_force_detection() {
    // Setup test environment
    let db = setup_test_db().await;
    let redis = setup_test_redis().await;
    let engine = DetectionEngine::new_test(db, redis);
    
    // Send 4 failed logins (should NOT alert)
    for _ in 0..4 {
        let log = create_failed_login("192.168.1.100");
        let alert = engine.process_log(log).await;
        assert!(alert.is_none());
    }
    
    // Send 5th failed login (SHOULD alert)
    let log = create_failed_login("192.168.1.100");
    let alert = engine.process_log(log).await;
    assert!(alert.is_some());
    
    // Verify alert in database
    let alerts = db.get_open_alerts_by_ip("192.168.1.100").await.unwrap();
    assert_eq!(alerts.len(), 1);
}