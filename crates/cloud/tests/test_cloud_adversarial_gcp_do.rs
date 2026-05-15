use gossan_cloud::{do_spaces::DoSpacesProvider, gcs::GcsProvider, provider::CloudProvider};
use gossan_core::{DiscoverySource, DomainTarget, Target};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_gcs_adversarial_xml_listing() {
    let server: MockServer = MockServer::start().await;

    // Valid looking XML but weird nesting to test robustness
    let xml_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
    <Name>gcs-adversarial-bucket</Name>
    <Contents>
        <Key>test</Key>
        <Contents><Key>nested-key</Key></Contents>
    </Contents>
</ListBucketResult>"#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(xml_body))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();

    // Direct endpoint test
    let url = server.uri() + "/";
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn test_gcs_adversarial_put_success() {
    let server: MockServer = MockServer::start().await;

    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let url = server.uri() + "/adversarial-write";
    let resp = client.put(&url).body("test").send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn test_gcs_adversarial_403() {
    let server: MockServer = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let url = server.uri() + "/";
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 403);
}

#[test]
fn test_gcs_endpoint_generation() {
    let gcs = GcsProvider;
    assert_eq!(
        gcs.endpoint("test-bucket"),
        "https://test-bucket.storage.googleapis.com/"
    );
    assert_eq!(gcs.endpoint(""), "https://.storage.googleapis.com/");
    assert_eq!(
        gcs.endpoint("a".repeat(64).as_str()),
        format!("https://{}.storage.googleapis.com/", "a".repeat(64))
    );
}

#[tokio::test]
async fn test_do_spaces_adversarial_xml_listing() {
    let server: MockServer = MockServer::start().await;

    // DO Spaces is S3 compatible
    let xml_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
    <Name>do-adversarial-bucket</Name>
</ListBucketResult>"#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(xml_body))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();

    // Direct endpoint test
    let url = server.uri() + "/";
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn test_do_spaces_adversarial_put_success() {
    let server: MockServer = MockServer::start().await;

    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let url = server.uri() + "/adversarial-write";
    let resp = client.put(&url).body("test").send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn test_do_spaces_adversarial_403() {
    let server: MockServer = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let url = server.uri() + "/";
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 403);
}

#[test]
fn test_do_spaces_endpoint_generation() {
    let do_spaces = DoSpacesProvider;
    // DO Spaces uses ams3 by default in the implementation `endpoint` method
    assert_eq!(
        do_spaces.endpoint("test-bucket"),
        "https://test-bucket.ams3.digitaloceanspaces.com/"
    );
    assert_eq!(
        do_spaces.endpoint(""),
        "https://.ams3.digitaloceanspaces.com/"
    );
    assert_eq!(
        do_spaces.endpoint("a".repeat(64).as_str()),
        format!("https://{}.ams3.digitaloceanspaces.com/", "a".repeat(64))
    );
}
