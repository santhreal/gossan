//! API-key gating contract: every paid-API origin scanner must
//! return Ok(empty) without making a network call when its API key
//! is absent. Per GOSSAN_LEGENDARY A16 negative-path requirements.
//!
//! The point: a CI run with no API keys should still complete, just
//! with reduced source coverage. We assert each source's scan()
//! function honors that contract and never panics on missing keys.

use gossan_core::Config;
use gossan_origin::sources;

fn empty_config() -> Config {
    let mut cfg = Config::default();
    cfg.api_keys.clear();
    cfg
}

fn test_client(cfg: &Config) -> gossan_core::ScanClient {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hickory_resolver::TokioAsyncResolver;
    use std::sync::Arc;
    let resolver = Arc::new(TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    ));
    gossan_core::ScanClient::from_config(cfg, resolver).expect("client")
}

#[tokio::test]
async fn censys_skips_cleanly_without_api_keys() {
    let cfg = empty_config();
    let client = test_client(&cfg);
    let r = sources::censys::scan("example.com", &cfg, &client).await;
    assert!(r.is_ok(), "censys must Ok when keys are absent: {:?}", r);
    assert!(
        r.unwrap().is_empty(),
        "censys must return empty candidates when keys are absent"
    );
}

#[tokio::test]
async fn dnsdb_skips_cleanly_without_api_keys() {
    let cfg = empty_config();
    let client = test_client(&cfg);
    let r = sources::dnsdb::scan("example.com", &cfg, &client).await;
    assert!(r.is_ok(), "dnsdb must Ok when keys are absent: {:?}", r);
    assert!(r.unwrap().is_empty());
}

#[tokio::test]
async fn passivetotal_skips_cleanly_without_api_keys() {
    let cfg = empty_config();
    let client = test_client(&cfg);
    let r = sources::passivetotal::scan("example.com", &cfg, &client).await;
    assert!(
        r.is_ok(),
        "passivetotal must Ok when keys are absent: {:?}",
        r
    );
    assert!(r.unwrap().is_empty());
}

#[tokio::test]
async fn circl_skips_cleanly_without_api_keys() {
    let cfg = empty_config();
    let client = test_client(&cfg);
    let r = sources::circl::scan("example.com", &cfg, &client).await;
    assert!(r.is_ok(), "circl must Ok when keys are absent: {:?}", r);
    assert!(r.unwrap().is_empty());
}
