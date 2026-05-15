use gossan_core::{HostTarget, Protocol, ServiceTarget, Target};
use gossan_techstack::bridge::probe;
use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

fn web_target(host: &str, port: u16) -> ServiceTarget {
    ServiceTarget {
        host: HostTarget {
            ip: "127.0.0.1".parse().unwrap(),
            domain: Some(host.to_string()),
        },
        port,
        protocol: Protocol::Tcp,
        banner: None,
        tls: port == 443,
    }
}

#[tokio::test]
async fn pipeline_deduplicates_and_implies() {
    let mock_server = MockServer::start().await;

    // Return headers that match both WordPress and a generic PHP cookie,
    // plus a React body that should imply Node.js and webpack.
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Set-Cookie", "wordpress_test_cookie=WP+Cookie+check")
                .insert_header("X-Powered-By", "PHP/7.4.3")
                .set_body_string(
                    r#"<html><body><script>window.__NUXT__ = {};</script></body></html>"#,
                ),
        )
        .mount(&mock_server)
        .await;

    let svc = web_target(
        &mock_server.address().ip().to_string(),
        mock_server.address().port(),
    );
    let client = reqwest::Client::new();
    let (asset, _findings) = probe(&client, svc).await.expect("probe should succeed");

    let names: Vec<&str> = asset.tech.iter().map(|t| t.name.as_str()).collect();

    // Postprocess should have deduplicated WordPress if there were duplicate rules.
    assert_eq!(
        names.iter().filter(|&&n| n == "WordPress").count(),
        1,
        "WordPress should appear exactly once after dedup"
    );

    // Implied expansion should have added inferred technologies.
    // Nuxt implies Vue.js and Node.js.
    assert!(
        names.contains(&"Vue.js"),
        "Implied tech should include Vue.js from Nuxt"
    );
    assert!(
        names.contains(&"Node.js"),
        "Implied tech should include Node.js from Nuxt/Vue"
    );
}

#[tokio::test]
async fn pipeline_detects_modern_frameworks() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"<html><body><script>__RSC</script><script>__turbopack_load()</script></body></html>"#),
        )
        .mount(&mock_server)
        .await;

    let svc = web_target(
        &mock_server.address().ip().to_string(),
        mock_server.address().port(),
    );
    let client = reqwest::Client::new();
    let (asset, _findings) = probe(&client, svc).await.expect("probe should succeed");

    let names: Vec<&str> = asset.tech.iter().map(|t| t.name.as_str()).collect();

    assert!(
        names.contains(&"React Server Components"),
        "Should detect React Server Components"
    );
    assert!(names.contains(&"Turbopack"), "Should detect Turbopack");
}
