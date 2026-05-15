//! Netlas subdomain source.
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use crate::sources::{SubdomainSource, SourceRate};
use async_trait::async_trait;
use governor::DefaultDirectRateLimiter;

pub struct Netlas;

#[async_trait]
impl SubdomainSource for Netlas {
    fn name(&self) -> &'static str { "netlas" }
    fn requires_api_key(&self) -> bool { true }
    fn api_key_name(&self) -> &'static str { "NETLAS_API_KEY" }
    fn rate_limit(&self) -> SourceRate { SourceRate::per_second(1) }
    fn discovery_source(&self) -> DiscoverySource { DiscoverySource::Netlas }

    async fn query(
        &self,
        domain: &str,
        config: &Config,
        client: &reqwest::Client,
        limiter: &DefaultDirectRateLimiter,
    ) -> anyhow::Result<Vec<Target>> {
        
        let Some(_key) = crate::sources::get_api_key(config, "netlas", "NETLAS_API_KEY") else {
            return Ok(vec![]);
        };

        let url = format!("https://app.netlas.io/api/domains/?q=domain:*.{}&indices=&source_type=include&start=0&fields=*", domain);
        limiter.until_ready().await;
        let resp = client.get(&url).send().await?;
        let max_size = config.max_response_size;
        let bytes = gossan_core::read_response_limited(resp, max_size).await?;
        let mut seen = std::collections::HashSet::new();
        let domain_lower = domain.to_lowercase();
        
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        if let Some(arr) = json.get("items").and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(v) = item.get("data.domain").and_then(|v| v.as_str()) {
                    let candidate = v.trim().trim_start_matches("*.").to_lowercase();
                    if !candidate.contains('*') && crate::is_subdomain_of(&candidate, &domain_lower) {
                        seen.insert(candidate);
                    }
                }
            }
        }

        Ok(seen.into_iter().map(|d| Target::Domain(DomainTarget {
            domain: d,
            source: DiscoverySource::Netlas,
        })).collect())
    }
}
