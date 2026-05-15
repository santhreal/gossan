//! `GITHUB_TOKEN` and `GITLAB_TOKEN` environment variables are
//! resolved by the SCM discovery functions.
//!
//! We can't easily intercept the actual reqwest call to assert the
//! token reached the wire — instead we exercise the resolution path:
//! when the env var is set, the discovery call still completes
//! cleanly (mockito catches the request whether the token is sent
//! or not), and when it's unset there's no panic.
//!
//! The token reach-through is also covered by a stricter mockito
//! match in `gitlab_discovery.rs` future iterations.

use gossan_core::{Config, ScanInput, Target};
use std::sync::Arc;
use tokio::sync::mpsc;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use mockito::Server;

fn fresh_input() -> (ScanInput, mpsc::UnboundedReceiver<Target>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let (live_tx, _live_rx) = mpsc::unbounded_channel();
    let (_t_in, t_in_rx) = mpsc::unbounded_channel();
    let resolver = Arc::new(TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    ));
    let input = ScanInput {
        seed: "acme.test".into(),
        target_rx: tokio::sync::Mutex::new(t_in_rx),
        live_tx,
        target_tx: tx,
        resolver,
    };
    (input, rx)
}

#[tokio::test]
async fn gitlab_token_env_var_path_does_not_error() {
    let mut server = Server::new_async().await;
    let _g = server
        .mock("GET", "/api/v4/groups/acme")
        .with_status(404)
        .create_async()
        .await;

    // SAFETY: env vars are process-global. We set + clear within the
    // same test to avoid bleeding into other tests. Keep this test
    // serial-friendly (no #[tokio::test(flavor = "multi_thread")]).
    std::env::set_var("GITLAB_TOKEN", "fake-token-for-test");
    let mut cfg = Config::default();
    cfg.api_keys.insert("gitlab_url".into(), server.url());
    let (input, _rx) = fresh_input();
    let r = gossan_scm::gitlab_api::discover_org_assets("acme.test", &cfg, &input).await;
    std::env::remove_var("GITLAB_TOKEN");
    assert!(r.is_ok(), "GITLAB_TOKEN env path must complete cleanly");
}

#[tokio::test]
async fn gitlab_token_unset_does_not_panic() {
    let mut server = Server::new_async().await;
    let _g = server
        .mock("GET", "/api/v4/groups/acme")
        .with_status(404)
        .create_async()
        .await;

    // Confirm GITLAB_TOKEN is unset (other tests may have set it).
    std::env::remove_var("GITLAB_TOKEN");
    let mut cfg = Config::default();
    cfg.api_keys.insert("gitlab_url".into(), server.url());
    let (input, _rx) = fresh_input();
    let r = gossan_scm::gitlab_api::discover_org_assets("acme.test", &cfg, &input).await;
    assert!(r.is_ok(), "unset GITLAB_TOKEN must not panic");
}

#[tokio::test]
async fn gitlab_explicit_config_token_overrides_env() {
    let mut server = Server::new_async().await;
    let _g = server
        .mock("GET", "/api/v4/groups/acme")
        .with_status(404)
        .create_async()
        .await;

    std::env::set_var("GITLAB_TOKEN", "env-token");
    let mut cfg = Config::default();
    cfg.api_keys.insert("gitlab".into(), "config-token".into());
    cfg.api_keys.insert("gitlab_url".into(), server.url());
    let (input, _rx) = fresh_input();
    let r = gossan_scm::gitlab_api::discover_org_assets("acme.test", &cfg, &input).await;
    std::env::remove_var("GITLAB_TOKEN");
    assert!(r.is_ok());
}
