//! Pastebin subdomain source.
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use crate::sources::{SubdomainSource, SourceRate};
use async_trait::async_trait;
use governor::DefaultDirectRateLimiter;

pub struct Pastebin;

#[async_trait]
impl SubdomainSource for Pastebin {
    fn name(&self) -> &'static str { "pastebin" }
    fn requires_api_key(&self) -> bool { false }
    fn api_key_name(&self) -> &'static str { "" }
    fn rate_limit(&self) -> SourceRate { SourceRate::per_second(1) }
    fn discovery_source(&self) -> DiscoverySource { DiscoverySource::PassiveDns }

    async fn query(
        &self,
        domain: &str,
        config: &Config,
        client: &reqwest::Client,
        limiter: &DefaultDirectRateLimiter,
    ) -> anyhow::Result<Vec<Target>> {
        let url = format!("https://psbdmp.ws/api/v3/dumpsearch/{}", domain);
        limiter.until_ready().await;
        let resp = client.get(&url).send().await?;
        let max_size = config.max_response_size;
        let bytes = gossan_core::read_response_limited(resp, max_size).await?;
        let mut seen = std::collections::HashSet::new();
        let domain_lower = domain.to_lowercase();

        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            if let Some(data) = json.get("data").and_then(|v| v.as_array()) {
                for item in data {
                    if let Some(text) = item.get("text").and_then(|v| v.as_str()) {
                        for word in text.split_whitespace() {
                            let word = word.trim().trim_end_matches('.').to_lowercase();
                            if crate::is_subdomain_of(&word, &domain_lower) {
                                seen.insert(word);
                            }
                        }
                    }
                }
            }
        }

        Ok(seen.into_iter().map(|d| Target::Domain(DomainTarget {
            domain: d,
            source: DiscoverySource::PassiveDns,
        })).collect())
    }
}
