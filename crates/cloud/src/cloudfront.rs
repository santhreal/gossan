//! CloudFront distribution discovery via CNAME probing.

use async_trait::async_trait;
use gossan_core::Target;
use secfinding::{Evidence, Finding, Severity};

use crate::provider::CloudProvider;

pub struct CloudFrontProvider;

#[async_trait]
impl CloudProvider for CloudFrontProvider {
    fn name(&self) -> &'static str {
        "cloudfront"
    }

    fn endpoint(&self, name: &str) -> String {
        format!("https://{}.cloudfront.net/", name)
    }

    async fn probe(
        &self,
        client: &reqwest::Client,
        name: &str,
        target: &Target,
    ) -> anyhow::Result<Vec<Finding>> {
        // CloudFront distributions have a length of exactly 14 alphanumeric characters.
        // E.g. d111111abcdef8.cloudfront.net
        let dist: String = name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_lowercase();

        // CloudFront distributions ID length logic
        // Though some org permutations might be checked, cloudfront domains usually look like d[0-9a-z]{13}
        if dist.len() > 63 {
            return Ok(vec![]);
        }

        let url = self.endpoint(name);
        let mut findings = Vec::new();

        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return Ok(vec![]),
        };

        let status = resp.status().as_u16();

        // If it's anything but a 403 matching "Bad request", it might be an active distribution.
        // Actually, we look for 200/403/404. Let's just flag 200 or 403 as existence.
        match status {
            200 | 401 | 403 => {
                let body = gossan_core::net::bounded_text(resp, 4 * 1024 * 1024)
                    .await
                    .unwrap_or_default();

                // CloudFront generic error when it doesn't exist usually is a DNS error or 403 Error from CloudFront.
                // An active one returns something else.
                // We'll report if it resolves and returns.
                if body.contains("<Error><Code>NoSuchDistribution</Code>") {
                    // Not found
                } else {
                    gossan_core::try_push_finding(
                        crate::finding_builder(
                            target,
                            Severity::Low,
                            format!("CloudFront Distribution found: {}", name),
                            format!(
                                "https://{}.cloudfront.net/ is resolving and returned HTTP {}. \
                                 This indicates an active CloudFront distribution.",
                                name, status
                            ),
                        )
                        .evidence(Evidence::HttpResponse {
                            status,
                            headers: vec![("url".into(), url.clone().into())],
                            body_excerpt: Some(body.chars().take(300).collect::<String>().into()),
                        })
                        .tag("cloudfront")
                        .tag("cloud")
                        .tag("cdn"),
                        &mut findings,
                    );
                }
            }
            _ => {}
        }

        Ok(findings)
    }
}
