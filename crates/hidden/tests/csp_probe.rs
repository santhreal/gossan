//! CSP probe integration tests — fires when the policy is missing
//! or weak; stays silent when the policy is sound.

use gossan_core::{Target, WebAssetTarget};
use gossan_hidden::csp;
use reqwest::{Client, Url};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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
async fn csp_with_unsafe_inline_fires() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).insert_header(
            "content-security-policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'",
        ))
        .mount(&server)
        .await;

    let client = Client::new();
    let findings = csp::probe(&client, &web_target(&format!("{}/", server.uri())))
        .await
        .expect("probe ok");
    assert!(
        findings.iter().any(|f| f.title().to_ascii_lowercase().contains("unsafe-inline")),
        "expected an unsafe-inline finding; got: {:?}",
        findings.iter().map(|f| f.title()).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn csp_with_wildcard_fires() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200).insert_header("content-security-policy", "script-src *"),
        )
        .mount(&server)
        .await;

    let client = Client::new();
    let findings = csp::probe(&client, &web_target(&format!("{}/", server.uri())))
        .await
        .expect("probe ok");
    assert!(
        !findings.is_empty(),
        "wildcard script-src must fire at least one finding"
    );
}

#[tokio::test]
async fn csp_strict_policy_produces_no_findings() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).insert_header(
            "content-security-policy",
            "default-src 'none'; script-src 'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        ))
        .mount(&server)
        .await;

    let client = Client::new();
    let findings = csp::probe(&client, &web_target(&format!("{}/", server.uri())))
        .await
        .expect("probe ok");
    // Strict policy with frame-ancestors 'none', no unsafe-inline,
    // no wildcard. Should yield zero findings.
    assert!(
        findings.is_empty(),
        "strict CSP should not fire findings; got: {:?}",
        findings.iter().map(|f| f.title()).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn csp_missing_header_fires() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("hello"))
        .mount(&server)
        .await;

    let client = Client::new();
    let findings = csp::probe(&client, &web_target(&format!("{}/", server.uri())))
        .await
        .expect("probe ok");
    assert!(
        findings.iter().any(|f| {
            let t = f.title().to_ascii_lowercase();
            t.contains("no content-security-policy") || t.contains("no csp")
                || t.contains("missing") || t.contains("not set")
        }),
        "missing CSP must produce a missing-header finding; got: {:?}",
        findings.iter().map(|f| f.title()).collect::<Vec<_>>()
    );
}
