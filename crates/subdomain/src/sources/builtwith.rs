//! BuiltWith subdomain source.
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use crate::sources::{SubdomainSource, SourceRate, get_api_key};
use async_trait::async_trait;
use governor::DefaultDirectRateLimiter;

pub struct BuiltWith;

#[async_trait]
impl SubdomainSource for BuiltWith {
    fn name(&self) -> &'static str { "builtwith" }
    fn requires_api_key(&self) -> bool { true }
    fn api_key_name(&self) -> &'static str { "BUILTWITH_API_KEY" }
    fn rate_limit(&self) -> SourceRate { SourceRate::per_second(1) }
    fn discovery_source(&self) -> DiscoverySource { DiscoverySource::PassiveDns }

    async fn query(
        &self,
        domain: &str,
        config: &Config,
        client: &reqwest::Client,
        limiter: &DefaultDirectRateLimiter,
    ) -> anyhow::Result<Vec<Target>> {
        let Some(key) = get_api_key(config, "builtwith", "BUILTWITH_API_KEY") else {
            return Ok(vec![]);
        };
        let url = format!("https://api.builtwith.com/v21/api.json?KEY={key}&LOOKUP={}", domain);
        limiter.until_ready().await;
        let resp = client.get(&url).send().await?;
        let max_size = config.max_response_size;
        let bytes = gossan_core::read_response_limited(resp, max_size).await?;
        let mut seen = std::collections::HashSet::new();
        let domain_lower = domain.to_lowercase();

        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            if let Some(results) = json.get("Results").and_then(|v| v.as_array()) {
                for result in results {
                    if let Some(meta) = result.get("Meta") {
                        if let Some(verticals) = meta.get("Verticals").and_then(|v| v.as_array()) {
                            for v in verticals {
                                if let Some(d) = v.get("Domain").and_then(|v| v.as_str()) {
                                    let candidate = d.trim().to_lowercase();
                                    if crate::is_subdomain_of(&candidate, &domain_lower) {
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
            source: DiscoverySource::PassiveDns,
        })).collect())
    }
}
