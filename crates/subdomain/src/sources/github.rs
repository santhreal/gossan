
//! GitHub code search subdomain source.
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use crate::sources::{SubdomainSource, SourceRate, get_api_key};
use async_trait::async_trait;
use governor::DefaultDirectRateLimiter;

pub struct GitHub;

#[async_trait]
impl SubdomainSource for GitHub {
    fn name(&self) -> &'static str { "github" }
    fn requires_api_key(&self) -> bool { true }
    fn api_key_name(&self) -> &'static str { "GITHUB_TOKEN" }
    fn rate_limit(&self) -> SourceRate { SourceRate::per_minute(10) }
    fn discovery_source(&self) -> DiscoverySource { DiscoverySource::GitHub }

    async fn query(
        &self,
        domain: &str,
        config: &Config,
        client: &reqwest::Client,
        limiter: &DefaultDirectRateLimiter,
    ) -> anyhow::Result<Vec<Target>> {
        let token = get_api_key(config, "github", "GITHUB_TOKEN");
        let mut req = client.get(format!(
            "https://api.github.com/search/code?q=extension:json+%22{}%22&per_page=100",
            domain
        ));
        if let Some(t) = &token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        req = req.header("Accept", "application/vnd.github+json");
        req = req.header("X-GitHub-Api-Version", "2022-11-28");

        limiter.until_ready().await;
        let max_size = config.max_response_size;
        let resp = req.send().await?;
        let bytes = gossan_core::read_response_limited(resp, max_size).await?;
        let json: serde_json::Value = serde_json::from_slice(&bytes)?;

        let mut seen = std::collections::HashSet::new();
        let pattern = format!(r"([a-zA-Z0-9_-]+\.{})", regex::escape(domain));
        let re = regex::Regex::new(&pattern)?;

        if let Some(items) = json.get("items").and_then(|v| v.as_array()) {
            for item in items {
                if let Some(text) = item.get("text_matches").and_then(|v| v.as_array()) {
                    for tm in text {
                        if let Some(fragment) = tm.get("fragment").and_then(|v| v.as_str()) {
                            let capped = &fragment[..fragment.len().min(8192)];
                            for cap in re.captures_iter(capped) {
                                if let Some(m) = cap.get(1) {
                                    let candidate = m.as_str().to_lowercase();
                                    if crate::is_subdomain_of(&candidate, domain) {
                                        seen.insert(candidate);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(seen.into_iter().map(|d| Target::Domain(DomainTarget {
            domain: d,
            source: DiscoverySource::GitHub,
        })).collect())
    }
}
