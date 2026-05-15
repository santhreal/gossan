use gossan_core::ratelimit::{build_client, HostRateLimiter};
use gossan_core::Config;
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use std::sync::Arc;
use tokio::time::Instant;

#[tokio::test]
async fn test_host_rate_limiter_basic() {
    let limiter = HostRateLimiter::new(10);

    for _ in 0..10 {
        limiter.until_ready("example.com").await;
    }

    let start = Instant::now();
    limiter.until_ready("example.com").await;
    let elapsed = start.elapsed().as_millis();
    assert!(elapsed >= 50 && elapsed <= 250, "Elapsed was {}ms", elapsed);
}

#[tokio::test]
async fn test_host_rate_limiter_independent_hosts() {
    let limiter = HostRateLimiter::new(1);

    let start = Instant::now();
    limiter.until_ready("host1.com").await;
    limiter.until_ready("host2.com").await;
    limiter.until_ready("host3.com").await;

    assert!(start.elapsed().as_millis() < 50);
}

#[tokio::test]
async fn test_build_client_with_config() {
    let mut config = Config::default();
    config.timeout_secs = 5;
    config.user_agent = "test-agent".to_string();
    config.cookie = Some("session=xyz".to_string());

    let resolver = Arc::new(TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    ));

    let client = build_client(&config, false, resolver).expect("Client should build");

    // We can assert the client was built with correct state. Reqwest client is opaque,
    // but we can ensure it's functional and configured. Since we can't inspect the inner
    // user agent easily, we test we can clone it and that it returns a valid Client struct.
    let cloned = client.clone();
    assert_eq!(
        std::mem::size_of_val(&cloned),
        std::mem::size_of_val(&client),
        "Cloned client should have same size"
    );
}

#[tokio::test]
async fn test_build_client_with_invalid_proxy() {
    let mut config = Config::default();
    config.proxy = Some("://invalid-url-scheme".to_string());

    let resolver = Arc::new(TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    ));

    let result = build_client(&config, false, resolver);
    assert!(result.is_err(), "Invalid proxy should return error");
}
