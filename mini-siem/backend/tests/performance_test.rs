#[tokio::test]
async fn test_high_throughput() {
    let engine = setup_detection_engine().await;
    
    // Send 10,000 logs
    let start = Instant::now();
    for _ in 0..10000 {
        let log = create_random_log();
        engine.process_log(log).await;
    }
    let elapsed = start.elapsed();
    
    println!("Processed 10,000 logs in {:?}", elapsed);
    assert!(elapsed < Duration::from_secs(1)); // Should be under 1 second
}