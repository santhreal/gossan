use gossan_core::ratelimit::{build_client, HostRateLimiter};
use gossan_core::Config;
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use std::sync::Arc;

use tokio::time::Instant;

#[tokio::test]
async fn test_host_rate_limiter_adversarial_zero() {
    let limiter = HostRateLimiter::new(0);

    let start = Instant::now();
    for _ in 0..3 {
        limiter.until_ready("example.com").await;
    }
    let elapsed = start.elapsed().as_millis();

    // If it clamps to 1 RPS instead of 0, 3 requests should take around ~2 seconds
    // depending on the initial burst tokens.
    // If it allows 0 RPS, it blocks forever (timeout would fail test)
    // If it allows infinite RPS, it takes 0 ms.
    // By checking elapsed > 500, we assert it enforces *some* rate limit > 0
    assert!(elapsed > 500, "Limiter created with 0 RPS should still enforce a positive rate limit (like 1 RPS), elapsed: {}ms", elapsed);
}

#[tokio::test]
async fn test_host_rate_limiter_adversarial_huge() {
    let limiter = HostRateLimiter::new(4294967295);

    let start = Instant::now();
    for _ in 0..10_000 {
        limiter.until_ready("example.com").await;
    }
    let elapsed = start.elapsed().as_millis();

    // Huge RPS should mean virtually no delay for 10,000 requests
    assert!(
        elapsed < 1000,
        "Huge RPS should not delay requests significantly, elapsed: {}ms",
        elapsed
    );
}

#[tokio::test]
async fn test_host_rate_limiter_adversarial_long_domain_string() {
    let limiter = HostRateLimiter::new(10);
    let domain = "a".repeat(100_000);

    // Should hash or store the long domain without panicking
    let start = Instant::now();
    limiter.until_ready(&domain).await;
    limiter.until_ready(&domain).await;
    let elapsed = start.elapsed().as_millis();

    // The rate limit should still apply properly even with huge strings
    assert!(
        elapsed < 500,
        "Long domain strings must not break the rate limiter functionality"
    );
}

#[tokio::test]
async fn test_build_client_adversarial_huge_timeout() {
    let mut config = Config::default();
    config.timeout_secs = u64::MAX;

    let resolver = Arc::new(TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    ));

    // A huge timeout might cause an overflow in reqwest's internal duration conversions,
    // so we expect it to either cleanly build or cleanly reject the config.
    let result = build_client(&config, false, resolver);
    match result {
        Ok(client) => {
            // If it built successfully, we verify we can clone it (meaning internal Arc is sound)
            let cloned = client.clone();
            drop(cloned);
        }
        Err(e) => {
            // If it failed, it must be a meaningful error string
            assert!(!e.to_string().is_empty(), "Error message must not be empty");
        }
    }
}
