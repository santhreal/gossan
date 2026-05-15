//! Quake subdomain source.
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use crate::sources::{SubdomainSource, SourceRate};
use async_trait::async_trait;
use governor::DefaultDirectRateLimiter;

pub struct Quake;

#[async_trait]
impl SubdomainSource for Quake {
    fn name(&self) -> &'static str { "quake" }
    fn requires_api_key(&self) -> bool { true }
    fn api_key_name(&self) -> &'static str { "QUAKE_API_KEY" }
    fn rate_limit(&self) -> SourceRate { SourceRate::per_second(0) }
    fn discovery_source(&self) -> DiscoverySource { DiscoverySource::Quake }

    async fn query(
        &self,
        domain: &str,
        config: &Config,
        client: &reqwest::Client,
        limiter: &DefaultDirectRateLimiter,
    ) -> anyhow::Result<Vec<Target>> {
        
        let Some(_key) = crate::sources::get_api_key(config, "quake", "QUAKE_API_KEY") else {
            return Ok(vec![]);
        };

        let url = format!("https://quake.360.net/api/v3/search/quake_service?query=domain:{}&start=0&size=1000", domain);
        limiter.until_ready().await;
        let resp = client.get(&url).send().await?;
        let max_size = config.max_response_size;
        let bytes = gossan_core::read_response_limited(resp, max_size).await?;
        let mut seen = std::collections::HashSet::new();
        let domain_lower = domain.to_lowercase();
        
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        if let Some(arr) = json.get("data").and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(v) = item.get("service.http.host").and_then(|v| v.as_str()) {
                    let candidate = v.trim().trim_start_matches("*.").to_lowercase();
                    if !candidate.contains('*') && crate::is_subdomain_of(&candidate, &domain_lower) {
                        seen.insert(candidate);
                    }
                }
            }
        }

        Ok(seen.into_iter().map(|d| Target::Domain(DomainTarget {
            domain: d,
            source: DiscoverySource::Quake,
        })).collect())
    }
}
