//! Viewdns subdomain source.
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use crate::sources::{SubdomainSource, SourceRate};
use async_trait::async_trait;
use governor::DefaultDirectRateLimiter;

pub struct Viewdns;

#[async_trait]
impl SubdomainSource for Viewdns {
    fn name(&self) -> &'static str { "viewdns" }
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
        
        let url = format!("https://viewdns.info/iphistory/?domain={}", domain);
        limiter.until_ready().await;
        let resp = client.get(&url).send().await?.error_for_status()?;
        let max_size = config.max_response_size;
        let bytes = gossan_core::read_response_limited(resp, max_size).await?;
        let mut seen = std::collections::HashSet::new();
        let domain_lower = domain.to_lowercase();
        
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let re = regex::Regex::new(&format!(r"(?i)([a-zA-Z0-9_-]+\.{})", regex::escape(domain)))?;
        for cap in re.captures_iter(&text) {
            if let Some(m) = cap.get(1) {
                let candidate = m.as_str().to_lowercase();
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
