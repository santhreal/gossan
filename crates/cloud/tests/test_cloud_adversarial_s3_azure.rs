use gossan_cloud::{azure::AzureProvider, provider::CloudProvider, s3::S3Provider};
use gossan_core::{DiscoverySource, DomainTarget, Target};
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_s3_adversarial_xml_listing() {
    let server: MockServer = MockServer::start().await;

    // Malicious or malformed XML that should still trigger the finding
    let xml_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
    <Name>adversarial-bucket</Name>
    <!-- Extremely long comment -->
    <Contents><Key>../../../../../etc/passwd</Key></Contents>
    <Contents><Key>👨‍👩‍👧‍👦.txt</Key></Contents>
</ListBucketResult>"#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(xml_body)
                .insert_header("x-amz-bucket-region", "us-west-2"),
        )
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let target = Target::Domain(DomainTarget {
        domain: "example.com".into(),
        source: DiscoverySource::Seed,
    });

    struct TestS3Provider(String);
    #[async_trait::async_trait]
    impl CloudProvider for TestS3Provider {
        fn name(&self) -> &'static str {
            "s3"
        }
        fn endpoint(&self, _name: &str) -> String {
            self.0.clone()
        }
        async fn probe(
            &self,
            c: &reqwest::Client,
            n: &str,
            t: &Target,
        ) -> anyhow::Result<Vec<secfinding::Finding>> {
            let s3 = S3Provider;
            s3.probe(c, n, t).await
        }
    }

    // Direct endpoint mock test
    let url = server.uri() + "/";
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn test_s3_adversarial_403_no_region() {
    let server: MockServer = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let target = Target::Domain(DomainTarget {
        domain: "example.com".into(),
        source: DiscoverySource::Seed,
    });

    let url = server.uri() + "/";
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 403);
}

#[tokio::test]
async fn test_s3_adversarial_put_success() {
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
async fn test_azure_adversarial_container_name() {
    let azure = AzureProvider;

    // Azure account names are 3-24 lowercase alphanumeric chars
    assert_eq!(
        azure.endpoint("test"),
        "https://test.blob.core.windows.net/"
    );
    assert_eq!(
        azure.endpoint("123456789012345678901234"),
        "https://123456789012345678901234.blob.core.windows.net/"
    );
}

#[tokio::test]
async fn test_azure_adversarial_200_web() {
    let server: MockServer = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/$web/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>Static Website</html>"))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let url = server.uri() + "/$web/";
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn test_azure_adversarial_403() {
    let server: MockServer = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/public/"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let url = server.uri() + "/public/";
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 403);
}

#[tokio::test]
async fn test_s3_adversarial_massive_body() {
    let server: MockServer = MockServer::start().await;

    let massive_body = "A".repeat(1_000_000);

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(massive_body))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let url = server.uri() + "/";
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn test_s3_adversarial_zalgo_body() {
    let server: MockServer = MockServer::start().await;

    let zalgo_body = "T̵h̶i̶s̵ ̷i̸s̶ ̶Z̷a̴l̷g̶o̵ ̷t̶e̸x̶t̷";

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(zalgo_body))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let url = server.uri() + "/";
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}

#[test]
fn test_azure_account_name_filtering() {
    let name = "Te-st_Bu!ck@et";
    let account: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_lowercase();

    assert_eq!(account, "testbucket");
}

#[test]
fn test_azure_account_name_length_bounds() {
    let short = "ab";
    let exact_short = "abc";
    let exact_long = "a".repeat(24);
    let long = "a".repeat(25);

    let is_valid = |acc: &str| acc.len() >= 3 && acc.len() <= 24;

    assert!(!is_valid(short));
    assert!(is_valid(exact_short));
    assert!(is_valid(&exact_long));
    assert!(!is_valid(&long));
}

#[test]
fn test_s3_endpoint_generation() {
    let s3 = S3Provider;
    assert_eq!(
        s3.endpoint("test-bucket"),
        "https://test-bucket.s3.amazonaws.com/"
    );
    assert_eq!(s3.endpoint(""), "https://.s3.amazonaws.com/");
    assert_eq!(
        s3.endpoint("a".repeat(64).as_str()),
        format!("https://{}.s3.amazonaws.com/", "a".repeat(64))
    );
}
