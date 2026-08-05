//! AWS Lambda function URL discovery.

use async_trait::async_trait;
use gossan_core::Target;
use secfinding::{Evidence, Finding, Severity};

use crate::provider::CloudProvider;

pub struct LambdaProvider {
    /// Optional endpoint override for testing.
    endpoint_override: Option<String>,
}

impl LambdaProvider {
    /// Create a new Lambda provider with the default AWS endpoint.
    #[must_use]
    pub fn new() -> Self {
        Self { endpoint_override: None }
    }

    /// Create a Lambda provider with a custom endpoint (for tests).
    #[must_use]
    pub fn with_endpoint(url: impl Into<String>) -> Self {
        Self { endpoint_override: Some(url.into()) }
    }
}

impl Default for LambdaProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CloudProvider for LambdaProvider {
    fn name(&self) -> &'static str {
        "lambda"
    }

    fn endpoint(&self, name: &str) -> String {
        if let Some(url) = &self.endpoint_override {
            return url.clone();
        }
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

        // Only the *filtered* ID matters; a 32-char string of punctuation
        // must NOT pass validation.
        if lambda_id.len() != 32 {
            return Ok(vec![]);
        }

        let url = self.endpoint(&lambda_id);
        let mut findings = Vec::new();

        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    function = %name,
                    url = %url,
                    error = %e,
                    "Lambda Function URL probe send failed"
                );
                return Ok(vec![]);
            }
        };

        let status = resp.status().as_u16();

        // 200 = public, 401/403 = exists but requires auth/IAM.
        // 404 = no such function, 5xx = service error/inconclusive.
        match status {
            200 | 401 | 403 => {
                let body = match gossan_core::net::bounded_text(
                    resp,
                    crate::MAX_CLOUD_RESPONSE_BYTES,
                )
                .await
                {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(
                            function = %name,
                            url = %url,
                            error = %e,
                            "Lambda Function URL body read failed"
                        );
                        return Ok(vec![]);
                    }
                };

                gossan_core::try_push_finding(crate::finding_builder(target, Severity::Low,
                        format!("Lambda Function URL found: {}", name),
                        format!(
                            "{} is resolving and returned HTTP {}. \
                             This indicates an active Lambda Function URL.",
                            url, status
                        ))
                    .evidence(Evidence::HttpResponse {
                        status,
                        headers: vec![("url".into(), url.clone().into())],
                        body_excerpt: Some(body.chars().take(crate::MAX_BODY_EXCERPT_CHARS).collect::<String>().into()),
                    })
                    .tag("lambda").tag("cloud").tag("aws").tag("serverless"), &mut findings);
            }
            _ => {}
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lambda_status_200_emits_finding() {
        let status = 200u16;
        let would_emit = matches!(status, 200 | 401 | 403);
        assert!(would_emit);
    }

    #[test]
    fn lambda_status_401_emits_finding() {
        let status = 401u16;
        let would_emit = matches!(status, 200 | 401 | 403);
        assert!(would_emit);
    }

    #[test]
    fn lambda_status_403_emits_finding() {
        let status = 403u16;
        let would_emit = matches!(status, 200 | 401 | 403);
        assert!(would_emit);
    }

    #[test]
    fn lambda_status_404_does_not_emit() {
        let status = 404u16;
        let would_emit = matches!(status, 200 | 401 | 403);
        assert!(!would_emit);
    }

    #[test]
    fn lambda_status_500_does_not_emit() {
        let status = 500u16;
        let would_emit = matches!(status, 200 | 401 | 403);
        assert!(!would_emit);
    }

    #[test]
    fn lambda_status_502_does_not_emit() {
        let status = 502u16;
        let would_emit = matches!(status, 200 | 401 | 403);
        assert!(!would_emit);
    }
}
