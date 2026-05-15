//! Swagger / OpenAPI spec exposure tests.
//!
//! Per GOSSAN_LEGENDARY A10: when an OpenAPI / Swagger spec is
//! exposed without auth, the probe must fire a finding. When the
//! spec is gated behind 401/403, no finding fires.

use gossan_core::{Target, WebAssetTarget};
use gossan_hidden::swagger;
use reqwest::{Client, Url};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SAMPLE_SPEC: &str = r#"{"openapi":"3.0.0","info":{"title":"x","version":"1.0"},"paths":{"/users":{"get":{"summary":"list users"}}}}"#;

fn web_target(url: &str) -> Target {
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
async fn swagger_exposed_fires_finding() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/swagger.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(SAMPLE_SPEC),
        )
        .mount(&server)
        .await;

    let client = Client::new();
    let target = web_target(&format!("{}/", server.uri()));
    let findings = swagger::probe(&client, &target, None).await.unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.title().to_lowercase().contains("openapi")
                || f.title().to_lowercase().contains("swagger")),
        "exposed swagger.json must fire a finding; got: {:?}",
        findings.iter().map(|f| f.title()).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn swagger_gated_behind_401_no_finding() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/swagger.json"))
        .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
        .mount(&server)
        .await;

    let client = Client::new();
    let target = web_target(&format!("{}/", server.uri()));
    let findings = swagger::probe(&client, &target, None).await.unwrap();
    assert!(
        findings.is_empty(),
        "401-gated swagger must NOT fire findings; got: {:?}",
        findings.iter().map(|f| f.title()).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn swagger_html_only_no_finding() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/swagger.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .set_body_string("<html>SPA shell</html>"),
        )
        .mount(&server)
        .await;

    let client = Client::new();
    let target = web_target(&format!("{}/", server.uri()));
    let findings = swagger::probe(&client, &target, None).await.unwrap();
    assert!(
        findings.is_empty(),
        "HTML response must not fire a swagger finding"
    );
}
