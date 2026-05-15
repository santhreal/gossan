//! AWS API Gateway endpoint probing.

use async_trait::async_trait;
use gossan_core::Target;
use secfinding::{Evidence, Finding, Severity};

use crate::provider::CloudProvider;

pub struct ApiGatewayProvider;

#[async_trait]
impl CloudProvider for ApiGatewayProvider {
    fn name(&self) -> &'static str {
        "apigateway"
    }

    fn endpoint(&self, name: &str) -> String {
        // API Gateway URLs generally take the form: https://{api_id}.execute-api.{region}.amazonaws.com/
        // For probing, we can just use a common region like us-east-1.
        format!("https://{}.execute-api.us-east-1.amazonaws.com/", name)
    }

    async fn probe(
        &self,
        client: &reqwest::Client,
        name: &str,
        target: &Target,
    ) -> anyhow::Result<Vec<Finding>> {
        let url = self.endpoint(name);
        let mut findings = Vec::new();

        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return Ok(vec![]),
        };

        let status = resp.status().as_u16();

        // An active API Gateway typically returns 403 Missing Authentication Token if accessed directly
        // at the root without a valid stage/route, or potentially a 200/404 if a root route is defined.
        if status == 403 || status == 404 || status == 200 || status == 401 {
            let body = gossan_core::net::bounded_text(resp, 4 * 1024 * 1024)
                .await
                .unwrap_or_default();

            // "Missing Authentication Token" is the classic AWS API Gateway error for a missing route
            if body.contains("Missing Authentication Token")
                || status == 200
                || status == 401
                || status == 404
            {
                gossan_core::try_push_finding(crate::finding_builder(target, Severity::Low,
                        format!("API Gateway found: {}", name),
                        format!(
                            "https://{}.execute-api.us-east-1.amazonaws.com/ is resolving and returned HTTP {}. \
                             This indicates an active AWS API Gateway endpoint.",
                            name, status
                        ))
                    .evidence(Evidence::HttpResponse {
                        status,
                        headers: vec![("url".into(), url.clone().into())],
                        body_excerpt: Some(body.chars().take(300).collect::<String>().into()),
                    })
                    .tag("apigateway").tag("cloud").tag("aws"), &mut findings);
            }
        }

        Ok(findings)
    }
}
