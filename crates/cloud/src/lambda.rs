//! AWS Lambda function URL discovery.

use async_trait::async_trait;
use gossan_core::Target;
use secfinding::{Evidence, Finding, Severity};

use crate::provider::CloudProvider;

pub struct LambdaProvider;

#[async_trait]
impl CloudProvider for LambdaProvider {
    fn name(&self) -> &'static str {
        "lambda"
    }

    fn endpoint(&self, name: &str) -> String {
        // Lambda Function URLs generally take the form: https://{url_id}.lambda-url.{region}.on.aws/
        format!("https://{}.lambda-url.us-east-1.on.aws/", name)
    }

    async fn probe(
        &self,
        client: &reqwest::Client,
        name: &str,
        target: &Target,
    ) -> anyhow::Result<Vec<Finding>> {
        // Lambda URL IDs are exactly 32 lowercase alphanumeric characters
        let lambda_id: String = name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_lowercase();

        if lambda_id.len() != 32 && name.len() != 32 {
            return Ok(vec![]);
        }

        let url = self.endpoint(name);
        let mut findings = Vec::new();

        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return Ok(vec![]),
        };

        let status = resp.status().as_u16();

        // If it's a 403 Forbidden, it might be IAM authenticated.
        // If it's 200, it's public.
        // A non-existent lambda URL usually just doesn't resolve (DNS NXDOMAIN).
        match status {
            200 | 401 | 403 | 404 | 500 | 502 => {
                let body = gossan_core::net::bounded_text(resp, 4 * 1024 * 1024)
                    .await
                    .unwrap_or_default();

                gossan_core::try_push_finding(crate::finding_builder(target, Severity::Low,
                        format!("Lambda Function URL found: {}", name),
                        format!(
                            "https://{}.lambda-url.us-east-1.on.aws/ is resolving and returned HTTP {}. \
                             This indicates an active Lambda Function URL.",
                            name, status
                        ))
                    .evidence(Evidence::HttpResponse {
                        status,
                        headers: vec![("url".into(), url.clone().into())],
                        body_excerpt: Some(body.chars().take(300).collect::<String>().into()),
                    })
                    .tag("lambda").tag("cloud").tag("aws").tag("serverless"), &mut findings);
            }
            _ => {}
        }

        Ok(findings)
    }
}
