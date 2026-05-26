//! Backup-file probe must not be fooled by soft-404 / catch-all
//! servers. The `/index.html.bak` check carries neither a magic-byte
//! nor a content probe, so before the baseline guard it fired on ANY
//! 200  -  a guaranteed false positive on SPA-catch-all / WAF origins.

use gossan_core::testkit::web_target;
use gossan_hidden::backup_files;
use gossan_core::ScanClient as Client;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

// `web_target` is now the shared `gossan_core::testkit::web_target`.

/// Adversarial: a catch-all server answers 200 with the SAME app-shell
/// body for every path  -  including the baseline probes and
/// `/index.html.bak`. No backup was recovered; the probe must stay
/// silent.
#[tokio::test]
async fn no_false_positive_on_catch_all_server() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<html><body>App Shell  -  single page app</body></html>"),
        )
        .mount(&server)
        .await;

    let client = gossan_core::ScanClient::default_client();
    let target = web_target(&server.uri());
    let rate_limiter = std::sync::Arc::new(gossan_hidden::HostRateLimiter::new(0));
    let findings = backup_files::probe(&client, &target, &rate_limiter, "127.0.0.1").await.unwrap();

    assert!(
        findings.is_empty(),
        "catch-all 200 must not yield backup findings, got: {:?}",
        findings.iter().map(|f| f.title()).collect::<Vec<_>>()
    );
}

/// Negative twin: the server 404s for nonexistent paths (so the
/// baseline is a real 404), but `/index.html.bak` returns a DISTINCT
/// 200 body  -  a genuinely recovered backup. The finding MUST fire, so
/// the fix is precise and not a blanket suppression.
#[tokio::test]
async fn still_fires_on_a_real_distinct_backup() {
    let server = MockServer::start().await;

    // Baseline probes (`/.gossan-baseline-*`) → real 404.
    Mock::given(method("GET"))
        .and(path_regex(r"^/\.gossan-baseline-"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&server)
        .await;

    // The actual exposed backup  -  distinct 200 content.
    Mock::given(method("GET"))
        .and(path("/index.html.bak"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<?php $db_pass = 'pr0d-s3cret'; // recovered source ?>"),
        )
        .mount(&server)
        .await;

    let client = gossan_core::ScanClient::default_client();
    let target = web_target(&server.uri());
    let rate_limiter = std::sync::Arc::new(gossan_hidden::HostRateLimiter::new(0));
    let findings = backup_files::probe(&client, &target, &rate_limiter, "127.0.0.1").await.unwrap();

    assert_eq!(
        findings.len(),
        1,
        "expected exactly the index.html.bak finding, got: {:?}",
        findings.iter().map(|f| f.title()).collect::<Vec<_>>()
    );
    assert!(
        findings[0].title().contains("index.html backup exposed"),
        "unexpected finding: {}",
        findings[0].title()
    );
}
