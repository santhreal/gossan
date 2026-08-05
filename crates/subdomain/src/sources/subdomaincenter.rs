//! Subdomaincenter subdomain source.
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use crate::sources::{SubdomainSource, SourceRate};
use async_trait::async_trait;
use governor::DefaultDirectRateLimiter;

pub struct Subdomaincenter;

#[async_trait]
impl SubdomainSource for Subdomaincenter {
    fn name(&self) -> &'static str { "subdomaincenter" }
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
        
        let url = format!("https://api.subdomain.center/?domain={}", domain);
        limiter.until_ready().await;
        let resp = client.get(&url).send().await?.error_for_status()?;
        let max_size = config.max_response_size;
        let bytes = gossan_core::read_response_limited(resp, max_size).await?;
        let mut seen = std::collections::HashSet::new();
        let domain_lower = domain.to_lowercase();
        
        let val: serde_json::Value = serde_json::from_slice(&bytes)?;
        if let Some(arr) = val.as_array() {
            for item in arr {
                let name = item.as_str()
                    .or_else(|| item.get("subdomain").and_then(|v| v.as_str()));
                if let Some(name) = name {
                    let candidate = name.trim().trim_start_matches("*.").to_lowercase();
                    if !candidate.contains('*') && crate::is_subdomain_of(&candidate, &domain_lower) {
                        seen.insert(candidate);
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
