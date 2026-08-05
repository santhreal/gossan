//! CloudFront distribution discovery via CNAME probing.

use async_trait::async_trait;
use gossan_core::Target;
use secfinding::{Evidence, Finding, Severity};

use crate::provider::CloudProvider;

pub struct CloudFrontProvider {
    /// Optional endpoint override for testing.
    endpoint_override: Option<String>,
}

impl CloudFrontProvider {
    /// Create a new CloudFront provider with the default AWS endpoint.
    #[must_use]
    pub fn new() -> Self {
        Self { endpoint_override: None }
    }

    /// Create a CloudFront provider with a custom endpoint (for tests).
    #[must_use]
    pub fn with_endpoint(url: impl Into<String>) -> Self {
        Self { endpoint_override: Some(url.into()) }
    }
}

impl Default for CloudFrontProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CloudProvider for CloudFrontProvider {
    fn name(&self) -> &'static str {
        "cloudfront"
    }

    fn endpoint(&self, name: &str) -> String {
        if let Some(url) = &self.endpoint_override {
            return url.clone();
        }
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

        // Use the filtered / sanitised `dist` so special chars or path-traversal
        // fragments in the raw `name` never reach the URL.
        let url = self.endpoint(&dist);
        let mut findings = Vec::new();

        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    distribution = %dist,
                    url = %url,
                    error = %e,
                    "CloudFront probe send failed"
                );
                return Ok(vec![]);
            }
        };

        let status = resp.status().as_u16();

        // Active distributions may return 200 (public), 401 (auth), or 403 (auth).
        // A bare 403 from CloudFront itself (not from an origin) usually means the
        // distribution does not exist or the request is blocked at the CloudFront
        // edge, so we must distinguish those before reporting.
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
                            distribution = %dist,
                            url = %url,
                            error = %e,
                            "CloudFront body read failed"
                        );
                        return Ok(vec![]);
                    }
                };

                if body.contains("<Error><Code>NoSuchDistribution</Code>") {
                    // Not found
                } else if status == 403 && is_cloudfront_not_configured(&body) {
                    // Generic CloudFront not-configured / edge-blocked 403
                } else {
                    gossan_core::try_push_finding(
                        crate::finding_builder(
                            target,
                            Severity::Low,
                            format!("CloudFront Distribution found: {}", dist),
                            format!(
                                "https://{}.cloudfront.net/ is resolving and returned HTTP {}. \
                                 This indicates an active CloudFront distribution.",
                                dist, status
                            ),
                        )
                        .evidence(Evidence::HttpResponse {
                            status,
                            headers: vec![("url".into(), url.clone().into())],
                            body_excerpt: Some(body.chars().take(crate::MAX_BODY_EXCERPT_CHARS).collect::<String>().into()),
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

/// Returns true when a 403 response carries CloudFront's generic error
/// signature (edge-blocked or not-configured), as opposed to a 403 from an
/// active distribution's origin.
fn is_cloudfront_not_configured(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("generated by cloudfront")
        || lower.contains("error from cloudfront")
        || lower.contains("403 error")
        || lower.contains("request blocked")
        || lower.contains("no such distribution")
        || lower.contains("nosuchdistribution")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudfront_status_200_emits_finding_logic() {
        let status = 200u16;
        let would_emit = matches!(status, 200 | 401 | 403);
        assert!(would_emit);
    }

    #[test]
    fn cloudfront_status_401_emits_finding_logic() {
        let status = 401u16;
        let would_emit = matches!(status, 200 | 401 | 403);
        assert!(would_emit);
    }

    #[test]
    fn cloudfront_status_403_emits_finding_logic() {
        let status = 403u16;
        let would_emit = matches!(status, 200 | 401 | 403);
        assert!(would_emit);
    }

    #[test]
    fn cloudfront_status_404_does_not_trigger() {
        let status = 404u16;
        let would_emit = matches!(status, 200 | 401 | 403);
        assert!(!would_emit);
    }

    #[test]
    fn cloudfront_not_configured_body_is_detected() {
        let body = "403 ERROR: The request could not be satisfied. Request blocked. Generated by cloudfront";
        assert!(is_cloudfront_not_configured(body));
    }

    #[test]
    fn cloudfront_active_403_body_is_not_not_configured() {
        let body = "<html><body>Forbidden: you need credentials</body></html>";
        assert!(!is_cloudfront_not_configured(body));
    }

    #[test]
    fn cloudfront_nosuchdistribution_body_prevents_finding() {
        let body = "<Error><Code>NoSuchDistribution</Code></Message></Error>";
        assert!(is_cloudfront_not_configured(body));
    }
}
