use gossan_core::{Target, WebAssetTarget};
use reqwest::{Client, Url};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use gossan_hidden::dependency_confusion;
use gossan_hidden::cors;

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
async fn test_dependency_confusion_gap_incomplete_manifest_missing_heurstic() {
    let server = MockServer::start().await;
    
    // Create a package.json that lacks the 'dependencies' and 'name' field, 
    // but clearly IS a package.json in other ways (e.g., 'version', 'scripts')
    // and is exposed at /package.json.
    // The current probe relies heavily on `body.contains("\"dependencies\"") || body.contains("\"name\"")`
    // This is a gap: an exposed package.json without those strings might be missed, even if it has 'devDependencies'
    // or simply exposes project structure.
    
    Mock::given(method("GET"))
        .and(path("/package.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{ "version": "1.0.0", "devDependencies": { "@internal/tools": "1.0.0" } }"#))
        .mount(&server)
        .await;

    let client = Client::new();
    let target = create_mock_target(&server.uri());

    let findings = dependency_confusion::probe(&client, &target).await.unwrap();
    
    // We expect it to find a finding since this is a valid package.json with devDependencies that could be confused.
    // This test will likely fail because the current implementation only looks for "dependencies" and "name".
    // This failing test serves as a finding in the engine as required by the Santh gap testing philosophy.
    assert!(!findings.is_empty(), "Gap: Probe missed a package.json with devDependencies and no name/dependencies");
}

#[tokio::test]
async fn test_cors_gap_regex_origin_reflection() {
    let server = MockServer::start().await;
    
    // A common real-world CORS misconfiguration is regex reflection, 
    // e.g., anything matching `.*\.example\.com` is reflected.
    // The current probe tests for prefix mismatch `https://evil-example.com`.
    // It doesn't test for `https://example.com.evil.com` (suffix mismatch).
    
    Mock::given(method("GET"))
        .and(path("/"))
        .and(wiremock::matchers::header("Origin", "https://example.com.evil.com"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("access-control-allow-origin", "https://example.com.evil.com")
        )
        .mount(&server)
        .await;

    let client = Client::new();
    let target = create_mock_target(&server.uri());

    let findings = cors::probe(&client, &target).await.unwrap();
    
    // We expect the probe to find this because it's a critical misconfiguration.
    // However, it currently ONLY tests `https://evil-{domain}`.
    // Therefore, this will fail.
    assert!(!findings.is_empty(), "Gap: Probe does not check for suffix-based origin regex bypasses (example.com.evil.com)");
}
