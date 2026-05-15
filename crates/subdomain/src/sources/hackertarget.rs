//! Hackertarget subdomain source.
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use crate::sources::{SubdomainSource, SourceRate};
use async_trait::async_trait;
use governor::DefaultDirectRateLimiter;

pub struct Hackertarget;

#[async_trait]
impl SubdomainSource for Hackertarget {
    fn name(&self) -> &'static str { "hackertarget" }
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
        
        let url = format!("https://api.hackertarget.com/hostsearch/?q={}", domain);
        limiter.until_ready().await;
        let resp = client.get(&url).send().await?;
        let max_size = config.max_response_size;
        let text = String::from_utf8(gossan_core::read_response_limited(resp, max_size).await?)?;
        let mut seen = std::collections::HashSet::new();
        let domain_lower = domain.to_lowercase();
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with("error") || line.starts_with("<") {
                continue;
            }
            if let Some(field) = line.split(',').nth(0) {
                let candidate = field.trim().trim_end_matches('.').to_lowercase();
                if crate::is_subdomain_of(&candidate, &domain_lower) {
                    seen.insert(candidate);
                }
            }
        }
        Ok(seen.into_iter().map(|d| Target::Domain(DomainTarget {
            domain: d,
            source: DiscoverySource::PassiveDns,
        })).collect())
    }
}
