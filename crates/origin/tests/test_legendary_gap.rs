use gossan_core::Config;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_gap_discover_origin_local_network_filtering() {
    let config = Config::default();

    // We expect localhost to not return loopback addresses, or at least for the engine
    // to strictly filter private/loopback WAF bypass origins.
    let candidates = gossan_origin::discover_origin("localhost", &config)
        .await
        .expect("Discover origin should not error out on localhost");

    // If the engine incorrectly returns 127.0.0.1 from the DNS resolution
    // of `localhost`, this test will fail, serving as a gap finding.
    for candidate in candidates {
        // Assert that the engine successfully filtered out loopbacks
        assert!(
            !candidate.ip.is_loopback(),
            "GAP FINDING: Engine should filter out loopback IPs"
        );
        // Assert that it filtered out private IPs (gap finding if it didn't)
        // In the codebase we saw `http_header` checked `is_loopback` but missed `is_private`.

        let is_private = match candidate.ip {
            std::net::IpAddr::V4(v4) => v4.is_private(),
            std::net::IpAddr::V6(_) => false, // Simplification for test
        };
        assert!(
            !is_private,
            "GAP FINDING: Engine should filter out private network IPs"
        );
    }
}

#[tokio::test]
async fn test_gap_favicon_hash_handles_large_responses() {
    // Spin up a local wiremock server that simulates a huge favicon response.
    let mock_server = MockServer::start().await;

    // Serve a 10MB payload to trigger potential memory exhaustion gaps
    // when using `.bytes().await` instead of a bounding stream.
    let huge_payload = vec![0u8; 10 * 1024 * 1024];

    Mock::given(method("GET"))
        .and(path("/favicon.ico"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(huge_payload))
        .mount(&mock_server)
        .await;

    // The favicon scanner now falls back to HTTP, so this will actually hit the mock server.
    let host = mock_server.address().ip().to_string();

    // Tight per-request timeout so this test can't burn 10s+ on each
    // of discover_origin's internal probes (Shodan / Censys / DNS /
    // favicon download). Without this the test was hanging on the
    // unbounded internal deadlines.
    let mut config = Config::default();
    config.timeout_secs = 2;
    config.host_delay_ms = 0;

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        gossan_origin::discover_origin(&host, &config),
    )
    .await
    .expect("discover_origin must return within 30s for an unauthenticated mock target");

    // Expect it to survive without panicking/OOMing.
    let candidates = result.expect("Should not panic or crash on large payload attempt");

    // No API keys are configured, so no candidates should be emitted.
    assert!(
        candidates.is_empty(),
        "Expected empty candidates since no Shodan/Censys key is configured"
    );
}
