use gossan_core::Config;
use gossan_origin::OriginCandidate;

fn candidate(ip: &str, method: &str, confidence: u8) -> OriginCandidate {
    OriginCandidate::new(ip.parse().unwrap(), method, confidence)
}

#[test]
fn test_origin_candidate_derived_traits() {
    let candidate1 = candidate("192.168.1.1", "test_method", 100);
    let candidate2 = candidate("192.168.1.1", "test_method", 100);
    let candidate3 = candidate("192.168.1.2", "test_method", 100);
    
    assert_eq!(candidate1, candidate2);
    assert_ne!(candidate1, candidate3);
    
    let cloned = candidate1.clone();
    assert_eq!(candidate1, cloned);
    
    // Test derived Ord (compares ip, then method, then confidence)
    assert!(candidate1 < candidate3);
}

#[tokio::test]
async fn test_discover_origin_local_domain() {
    let config = Config::default();
    // Use a domain that's guaranteed not to resolve to anything meaningful or leak real data,
    // to test that the parallel scanner runs without panic and aggregates results (likely empty).
    let result = gossan_origin::discover_origin("invalid.domain.that.does.not.exist.internal", &config).await;
    
    let candidates = result.expect("discover_origin should not fail on invalid domain");
    assert!(candidates.is_empty(), "Should have no candidates for a non-existent domain");
}

#[tokio::test]
async fn test_discover_origin_empty_domain() {
    let config = Config::default();
    let result = gossan_origin::discover_origin("", &config).await;
    let candidates = result.expect("discover_origin should return cleanly on empty domain");
    assert!(candidates.is_empty(), "Should have no candidates for empty domain");
}

#[test]
fn test_origin_candidate_serialization() {
    let candidate = candidate("192.168.1.1", "test_method", 100);
    
    let serialized = serde_json::to_string(&candidate).expect("Failed to serialize");
    assert!(serialized.contains("192.168.1.1"));
    assert!(serialized.contains("test_method"));
    assert!(serialized.contains("100"));
    
    let deserialized: OriginCandidate = serde_json::from_str(&serialized).expect("Failed to deserialize");
    assert_eq!(candidate, deserialized);
}
