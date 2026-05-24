//! The heapdump debug probe carries no `confirm_strings`  -  its only
//! legitimate signal is a binary `octet-stream` body. A 2xx with any
//! other content type (SPA catch-all, HTML error page) is NOT a heap
//! dump and must not be reported.

use gossan_core::testkit::web_target;
use gossan_hidden::debug_endpoints;
use gossan_core::ScanClient as Client;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// `web_target` is now the shared `gossan_core::testkit::web_target`.

/// Adversarial: a catch-all server answers 200 with an HTML app shell
/// for every path including `/actuator/heapdump`. Pre-fix the empty
/// `confirm_strings` auto-confirmed and emitted a Critical "Heap Dump
/// Exposed". It must now stay silent.
#[tokio::test]
async fn catch_all_html_is_not_a_heap_dump() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .set_body_string("<html><body>SPA shell</body></html>"),
        )
        .mount(&server)
        .await;

    let client = gossan_core::ScanClient::default_client();
    let target = web_target(&server.uri());
    let findings = debug_endpoints::probe(&client, &target).await.unwrap();

    assert!(
        !findings.iter().any(|f| f.title().contains("Heap Dump")),
        "catch-all HTML must not be reported as a heap dump: {:?}",
        findings.iter().map(|f| f.title()).collect::<Vec<_>>()
    );
}

/// Negative twin: a genuine heap dump (binary `octet-stream`) on the
/// actuator path MUST still be detected  -  the fix is precise, not a
/// blanket suppression of the heapdump probe.
#[tokio::test]
async fn real_octet_stream_heap_dump_still_detected() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/actuator/heapdump"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/octet-stream")
                .set_body_bytes(vec![0u8, 1, 2, 3, 4, 5, 6, 7]),
        )
        .mount(&server)
        .await;

    let client = gossan_core::ScanClient::default_client();
    let target = web_target(&server.uri());
    let findings = debug_endpoints::probe(&client, &target).await.unwrap();

    assert!(
        findings.iter().any(|f| f.title().contains("Heap Dump")),
        "a real octet-stream heap dump must still be detected, got: {:?}",
        findings.iter().map(|f| f.title()).collect::<Vec<_>>()
    );
}
