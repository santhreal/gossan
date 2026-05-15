
//! DNSdumpster subdomain source — CSRF-scraped HTML table.
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use crate::sources::{SubdomainSource, SourceRate};
use async_trait::async_trait;
use governor::DefaultDirectRateLimiter;

pub struct DnsDumpster;

#[async_trait]
impl SubdomainSource for DnsDumpster {
    fn name(&self) -> &'static str { "dnsdumpster" }
    fn requires_api_key(&self) -> bool { false }
    fn api_key_name(&self) -> &'static str { "" }
    fn rate_limit(&self) -> SourceRate { SourceRate::per_second(1) }
    fn discovery_source(&self) -> DiscoverySource { DiscoverySource::DnsDumpster }

    async fn query(
        &self,
        domain: &str,
        config: &Config,
        client: &reqwest::Client,
        limiter: &DefaultDirectRateLimiter,
    ) -> anyhow::Result<Vec<Target>> {
        let csrf_url = "https://dnsdumpster.com";
        limiter.until_ready().await;
        let csrf_resp = client.get(csrf_url).send().await?;
        let max_size = config.max_response_size;
        let csrf_text = String::from_utf8(
            gossan_core::read_response_limited(csrf_resp, max_size).await?
        )?;

        let csrf_token = csrf_text
            .split("csrfmiddlewaretoken")
            .nth(1)
            .and_then(|s| s.split("value=").nth(1))
            .and_then(|s| s.split('"').nth(1))
            .map(|s| s.to_string());

        let Some(token) = csrf_token else {
            tracing::warn!("dnsdumpster CSRF extraction failed");
            return Ok(vec![]);
        };

        limiter.until_ready().await;
        let post_resp = client
            .post("https://dnsdumpster.com/")
            .header("Referer", "https://dnsdumpster.com/")
            .form(&[("csrfmiddlewaretoken", token.as_str()), ("targetip", domain)])
            .send()
            .await?;

        let text = String::from_utf8(
            gossan_core::read_response_limited(post_resp, max_size).await?
        )?;

        let domain_lower = domain.to_lowercase();
        let mut seen = std::collections::HashSet::new();

        for line in text.lines() {
            let line_lower = line.to_lowercase();
            if line_lower.contains("<td>") && line_lower.contains(&domain_lower) {
                if let Some(start) = line.find("<td>") {
                    let inner = &line[start + 4..];
                    if let Some(end) = inner.find("</td>") {
                        let text = inner[..end]
                            .replace("<br/>", " ")
                            .replace("<br>", " ");
                        for part in text.split_whitespace() {
                            let part = part.trim().trim_end_matches('.').to_lowercase();
                            if crate::is_subdomain_of(&part, &domain_lower) {
                                seen.insert(part);
                            }
                        }
                    }
                }
            }
        }

        Ok(seen.into_iter().map(|d| Target::Domain(DomainTarget {
            domain: d,
            source: DiscoverySource::DnsDumpster,
        })).collect())
    }
}
