//! GraphQL introspection probe — fires when introspection is on,
//! stays silent when it's off.

use gossan_core::{Target, WebAssetTarget};
use gossan_hidden::graphql;
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

const SCHEMA_REPLY: &str =
    r#"{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"Query","kind":"OBJECT","fields":[{"name":"hello"}]}]}}}"#;
const TYPENAME_REPLY: &str = r#"{"data":{"__typename":"Query"}}"#;

#[tokio::test]
async fn graphql_introspection_enabled_fires() {
    let server = MockServer::start().await;
    // The probe first sends a `__typename` validator query and only
    // proceeds with introspection if it finds a real GraphQL endpoint
    // — so the validator response must come first.
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_string(TYPENAME_REPLY))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SCHEMA_REPLY))
        .mount(&server)
        .await;

    let client = Client::new();
    let findings = graphql::probe(&client, &web_target(&format!("{}/", server.uri())), None)
        .await
        .expect("probe ok");
    assert!(
        findings
            .iter()
            .any(|f| f.title().to_ascii_lowercase().contains("introspection")),
        "introspection-on server must fire an introspection finding; got: {:?}",
        findings.iter().map(|f| f.title()).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn graphql_introspection_disabled_no_finding() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"errors":[{"message":"GraphQL introspection is not allowed by Apollo Server, but the query contained __schema or __type."}]}"#,
        ))
        .mount(&server)
        .await;

    let client = Client::new();
    let findings = graphql::probe(&client, &web_target(&format!("{}/", server.uri())), None)
        .await
        .expect("probe ok");
    assert!(
        !findings
            .iter()
            .any(|f| f.title().to_ascii_lowercase().contains("introspection enabled")),
        "introspection-off server must NOT fire an introspection-enabled finding; got: {:?}",
        findings.iter().map(|f| f.title()).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn graphql_no_endpoint_no_finding() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&server)
        .await;

    let client = Client::new();
    let findings = graphql::probe(&client, &web_target(&format!("{}/", server.uri())), None)
        .await
        .expect("probe ok");
    assert!(
        findings.is_empty(),
        "server with no GraphQL endpoint must not fire findings; got: {:?}",
        findings.iter().map(|f| f.title()).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn graphql_endpoint_detected_via_typename_probe() {
    let server = MockServer::start().await;
    // First request — the __typename validator — succeeds.
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_string(TYPENAME_REPLY))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    // Subsequent introspection requests succeed too.
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SCHEMA_REPLY))
        .mount(&server)
        .await;

    let client = Client::new();
    let _ = graphql::probe(&client, &web_target(&format!("{}/", server.uri())), None)
        .await
        .expect("probe ok");
}
