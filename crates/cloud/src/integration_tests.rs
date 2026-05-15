use super::*;
use crate::provider::CloudProvider;
use gossan_core::{DiscoverySource, DomainTarget, Target};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_s3_public_listing_detection() {
    let server: MockServer = MockServer::start().await;

    // Mock S3 XML listing
    let xml_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>test-bucket</Name>
    <Contents><Key>secret.txt</Key></Contents>
</ListBucketResult>"#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(xml_body))
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
            let url = self.endpoint(n);
            let resp = c.get(&url).send().await?;
            let status = resp.status().as_u16();
            let body = resp.text().await?;

            let mut findings = Vec::new();
            if status == 200 && body.contains("<ListBucketResult") {
                findings.push(
                    crate::finding_builder(
                        t,
                        secfinding::Severity::Critical,
                        "Public Bucket",
                        "Exposed",
                    )
                    .build()
                    .unwrap(),
                );
            }
            Ok(findings)
        }
    }

    let provider = TestS3Provider(server.uri() + "/");
    let findings = provider
        .probe(&client, "test-bucket", &target)
        .await
        .unwrap();

    assert!(!findings.is_empty());
    assert!(findings[0].title().contains("Public Bucket"));
}
