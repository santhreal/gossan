use gossan_core::{Target, WebAssetTarget};
use reqwest::{Client, Url};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use secfinding::Severity;
use gossan_hidden::cors;
use gossan_hidden::dependency_confusion;

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
async fn test_cors_reflection_with_credentials() {
    let server = MockServer::start().await;
    
    Mock::given(method("GET"))
        .and(path("/"))
        .and(header("Origin", "https://evil.com"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("access-control-allow-origin", "https://evil.com")
                .insert_header("access-control-allow-credentials", "true"),
        )
        .mount(&server)
        .await;

    let client = Client::new();
    let target = create_mock_target(&server.uri());

    let findings = cors::probe(&client, &target).await.unwrap();
    
    assert!(!findings.is_empty(), "Expected findings for CORS reflection");
    let finding = findings.iter().find(|f| f.title() == "CORS: arbitrary origin reflected with credentials").unwrap();
    assert_eq!(finding.severity(), Severity::Critical);
}

#[tokio::test]
async fn test_cors_null_origin() {
    let server = MockServer::start().await;
    
    Mock::given(method("GET"))
        .and(path("/"))
        .and(header("Origin", "null"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("access-control-allow-origin", "null")
                .insert_header("access-control-allow-credentials", "true"),
        )
        .mount(&server)
        .await;

    let client = Client::new();
    let target = create_mock_target(&server.uri());

    let findings = cors::probe(&client, &target).await.unwrap();
    
    assert!(!findings.is_empty(), "Expected findings for CORS null origin");
    let finding = findings.iter().find(|f| f.title() == "CORS: null origin trusted").unwrap();
    assert_eq!(finding.severity(), Severity::Critical);
}

#[tokio::test]
async fn test_dependency_confusion_package_json() {
    let server = MockServer::start().await;
    
    Mock::given(method("GET"))
        .and(path("/package.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{ "name": "my-app", "dependencies": { "@internal/auth": "1.0.0" } }"#))
        .mount(&server)
        .await;

    let client = Client::new();
    let target = create_mock_target(&server.uri());

    let findings = dependency_confusion::probe(&client, &target).await.unwrap();
    
    assert!(!findings.is_empty(), "Expected findings for package.json exposure");
    assert!(findings[0].title().contains("package.json"));
}
