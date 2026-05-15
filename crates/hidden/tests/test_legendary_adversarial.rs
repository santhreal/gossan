use gossan_core::{Target, WebAssetTarget};
use gossan_hidden::cors;
use reqwest::{Client, Url};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn create_mock_target(url: &str) -> Target {
    Target::Web(Box::new(WebAssetTarget {
        url: Url::parse(url).unwrap(),
        service: gossan_core::ServiceTarget {
            host: gossan_core::HostTarget {
                ip: "127.0.0.1".parse().unwrap(),
                domain: Some("example.com".to_string()),
            },
            port: 80,
            protocol: gossan_core::Protocol::Tcp,
            banner: None,
            tls: false,
        },
        tech: vec![],
        status: 200,
        title: None,
        favicon_hash: None,
        body_hash: None,
        forms: vec![],
        params: vec![],
    }))
}

#[tokio::test]
async fn test_cors_huge_response_no_panic() {
    let server = MockServer::start().await;

    // Create a huge string (1MB+)
    let huge_body = "A".repeat(1024 * 1024);

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(huge_body)
                .insert_header("access-control-allow-origin", "https://evil.com"),
        )
        .mount(&server)
        .await;

    let client = Client::new();
    let target = create_mock_target(&server.uri());

    let findings = cors::probe(&client, &target).await.unwrap();

    // As long as it doesn't panic, it's a pass. We expect finding since it matched evil origin header.
    assert!(
        !findings.is_empty(),
        "Expected findings for CORS reflection on huge body"
    );
}

#[tokio::test]
async fn test_cors_invalid_headers_no_panic() {
    let server = MockServer::start().await;

    // Send invalid bytes in header if possible, or just extremely long header
    let huge_header = "evil.com".repeat(10000);

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("access-control-allow-origin", huge_header.as_str()),
        )
        .mount(&server)
        .await;

    let client = Client::new();
    let target = create_mock_target(&server.uri());

    let findings = cors::probe(&client, &target).await.unwrap();

    // Shouldn't panic, but shouldn't find anything because huge_header != https://evil.com
    assert!(findings.is_empty());
}
