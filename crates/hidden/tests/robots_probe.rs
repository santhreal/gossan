//! robots.txt probe smoke tests — verifies the probe extracts
//! disallow paths from a real robots response.

use gossan_core::{Target, WebAssetTarget};
use gossan_hidden::robots;
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
async fn robots_with_disallow_paths_fires() {
    let server = MockServer::start().await;
    let body = "User-agent: *\nDisallow: /admin\nDisallow: /api/internal\nSitemap: https://example.com/sitemap.xml\n";
    Mock::given(method("GET"))
        .and(path("/robots.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let client = Client::new();
    let target = web_target(&format!("{}/", server.uri()));
    let findings = robots::probe(&client, &target).await.unwrap();
    assert!(
        !findings.is_empty(),
        "robots.txt with disallow paths must fire findings; got {:?}",
        findings.iter().map(|f| f.title()).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn no_robots_no_finding() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/robots.txt"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&server)
        .await;

    let client = Client::new();
    let target = web_target(&format!("{}/", server.uri()));
    let findings = robots::probe(&client, &target).await.unwrap();
    assert!(findings.is_empty(), "404 robots.txt must yield no findings");
}

#[tokio::test]
async fn empty_robots_no_finding() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/robots.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let client = Client::new();
    let target = web_target(&format!("{}/", server.uri()));
    let findings = robots::probe(&client, &target).await.unwrap();
    assert!(findings.is_empty(), "empty robots.txt must yield no findings");
}
