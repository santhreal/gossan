//! gitlab_api::discover_org_assets emits a Repository target for
//! every project returned by /api/v4/groups/:name/projects.

use gossan_core::target::{ScmService, Target};
use gossan_core::{Config, ScanInput};
use gossan_scm::gitlab_api;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use mockito::Server;
use std::sync::Arc;
use tokio::sync::mpsc;

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
async fn emits_repository_target_per_project() {
    let mut server = Server::new_async().await;

    let _g = server
        .mock("GET", "/api/v4/groups/acme")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id": 42, "full_path": "acme"}"#)
        .create_async()
        .await;

    let _p = server
        .mock(
            "GET",
            mockito::Matcher::Regex(r"^/api/v4/groups/acme/projects.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"[
                {"http_url_to_repo":"https://gitlab.test/acme/api.git","default_branch":"main"},
                {"http_url_to_repo":"https://gitlab.test/acme/web.git","default_branch":"trunk"}
            ]"#,
        )
        .create_async()
        .await;

    let mut cfg = Config::default();
    cfg.api_keys.insert("gitlab_url".into(), server.url());

    let (input, mut rx) = fresh_input();

    gitlab_api::discover_org_assets("acme.test", &cfg, &input)
        .await
        .expect("discover ok");

    let mut got = Vec::new();
    while let Ok(t) = rx.try_recv() {
        got.push(t);
    }
    assert_eq!(got.len(), 2, "expected 2 repos, got {}", got.len());
    for t in &got {
        match t {
            Target::Repository(r) => {
                assert_eq!(r.service, ScmService::GitLab);
                assert!(r.url.as_str().starts_with("https://gitlab.test/acme/"));
            }
            _ => panic!("non-repo target emitted"),
        }
    }
}

#[tokio::test]
async fn group_404_is_soft_fail_no_panic_no_emit() {
    let mut server = Server::new_async().await;

    let _g = server
        .mock("GET", "/api/v4/groups/missing")
        .with_status(404)
        .with_body("not found")
        .create_async()
        .await;

    let mut cfg = Config::default();
    cfg.api_keys.insert("gitlab_url".into(), server.url());

    let (input, mut rx) = fresh_input();

    gitlab_api::discover_org_assets("missing.test", &cfg, &input)
        .await
        .expect("must not error on 404");

    assert!(
        rx.try_recv().is_err(),
        "no targets must be emitted on group 404"
    );
}

#[tokio::test]
async fn empty_group_name_short_circuits() {
    let mut cfg = Config::default();
    // Point at an unreachable host; if we accidentally hit the
    // network the test will hang/error. Empty leading-label must
    // short-circuit before any HTTP.
    cfg.api_keys
        .insert("gitlab_url".into(), "http://127.0.0.1:1".into());

    let (input, mut rx) = fresh_input();
    gitlab_api::discover_org_assets("", &cfg, &input)
        .await
        .expect("ok");
    assert!(rx.try_recv().is_err());
}
