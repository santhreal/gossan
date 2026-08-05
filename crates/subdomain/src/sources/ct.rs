//! Ct subdomain source.
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use crate::sources::{SubdomainSource, SourceRate};
use async_trait::async_trait;
use governor::DefaultDirectRateLimiter;

pub struct Ct;

#[async_trait]
impl SubdomainSource for Ct {
    fn name(&self) -> &'static str { "ct" }
    fn requires_api_key(&self) -> bool { false }
    fn api_key_name(&self) -> &'static str { "" }
    fn rate_limit(&self) -> SourceRate { SourceRate::per_second(1) }
    fn discovery_source(&self) -> DiscoverySource { DiscoverySource::CertificateTransparency }

    async fn query(
        &self,
        domain: &str,
        config: &Config,
        client: &reqwest::Client,
        limiter: &DefaultDirectRateLimiter,
    ) -> anyhow::Result<Vec<Target>> {
        
        let url = ctlog::crtsh_query_url(domain);
        limiter.until_ready().await;
        let resp = client.get(&url).send().await?.error_for_status()?;
        let max_size = config.max_response_size;
        let bytes = gossan_core::read_response_limited(resp, max_size).await?;
        let mut seen = std::collections::HashSet::new();
        let domain_lower = domain.to_lowercase();
        
        // Normalize via the canonical crt.sh parser (newline split, `*.`
        // strip, lowercase, wildcard/empty drop, dedup) then keep only
        // strict subdomains of the queried domain. Malformed bodies fail
        // the source (orchestrator emits source-error) instead of silent empty.
        let text = String::from_utf8_lossy(&bytes);
        for candidate in ctlog::parse_crtsh_hostnames(&text)? {
            if crate::is_subdomain_of(&candidate, &domain_lower) {
                seen.insert(candidate);
            }
        }

        Ok(seen.into_iter().map(|d| Target::Domain(DomainTarget {
            domain: d,
            source: DiscoverySource::CertificateTransparency,
        })).collect())
    }
}
