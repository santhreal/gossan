//! Adversarial inputs to `discover_origin`.
//!
//! Goal: confirm the engine doesn't panic / OOM / hang on hostile
//! domain strings. Each test runs with a tight config-side timeout
//! AND an outer tokio test deadline — without both, the unbounded
//! internal probes (Shodan + Censys + DNS + favicon HTTP) take
//! minutes per case and stall CI.

use gossan_core::Config;
use gossan_origin::OriginCandidate;
use std::net::IpAddr;
use std::time::Duration;

const PER_CASE_BUDGET: Duration = Duration::from_secs(20);

fn fast_config() -> Config {
    let mut c = Config::default();
    c.timeout_secs = 2;
    c.host_delay_ms = 0;
    c
}

fn candidate(ip: &str, method: &str, confidence: u8) -> OriginCandidate {
    OriginCandidate::new(ip.parse().unwrap(), method, confidence)
}

async fn probe(domain: &str) -> Vec<OriginCandidate> {
    let config = fast_config();
    let result = tokio::time::timeout(
        PER_CASE_BUDGET,
        gossan_origin::discover_origin(domain, &config),
    )
    .await
    .expect("discover_origin must complete within the per-case budget");
    result.expect("discover_origin must return Ok on adversarial input")
}

#[tokio::test]
async fn test_adversarial_discover_origin_huge_input() {
    let huge_domain = "a".repeat(1024 * 1024);
    let candidates = probe(&huge_domain).await;
    assert!(
        candidates.is_empty(),
        "Huge domain string should yield no candidates"
    );
}

#[tokio::test]
async fn test_adversarial_discover_origin_null_bytes() {
    let candidates = probe("example\0.com").await;
    assert!(
        candidates.is_empty(),
        "Null bytes domain should yield no candidates"
    );
}

#[tokio::test]
async fn test_adversarial_discover_origin_boundary_unicode() {
    let zalgo_domain = "e̵x̵a̵m̵p̵l̵e̵.c̵o̵m̵\u{200b}\u{200c}\u{200d}";
    let candidates = probe(zalgo_domain).await;
    assert!(
        candidates.is_empty(),
        "Malformed unicode domain should yield no candidates"
    );
}

#[tokio::test]
async fn test_adversarial_discover_origin_path_traversal() {
    let candidates = probe("../../../etc/passwd").await;
    assert!(
        candidates.is_empty(),
        "Path traversal payload should yield no candidates"
    );
}

#[tokio::test]
async fn test_adversarial_discover_origin_special_chars() {
    let candidates = probe("ex@mple.com/\r\nHost: evil.com").await;
    assert!(
        candidates.is_empty(),
        "Special chars domain should yield no candidates"
    );
}

#[test]
fn test_adversarial_candidate_deduplication_extreme_confidence() {
    // Check integer boundary behavior in sorting/dedup
    let mut candidates = vec![
        candidate("10.0.0.1", "method_a", 0),
        candidate("10.0.0.1", "method_b", 255), // u8 MAX
        candidate("10.0.0.2", "method_c", 128),
    ];

    // Sort by confidence, descending (matches discover_origin's order).
    candidates.sort_by(|a, b| b.confidence.cmp(&a.confidence));

    // Dedup by IP, keep the highest-confidence entry.
    let mut seen = std::collections::HashSet::new();
    candidates.retain(|c| seen.insert(c.ip));

    assert_eq!(candidates.len(), 2);

    let first = &candidates[0];
    assert_eq!(first.ip, "10.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(first.confidence, 255);
}
