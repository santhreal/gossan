//! Wayback Machine subdomain source.
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use crate::sources::{SubdomainSource, SourceRate};
use async_trait::async_trait;
use governor::DefaultDirectRateLimiter;

pub struct Wayback;

#[async_trait]
impl SubdomainSource for Wayback {
    fn name(&self) -> &'static str { "wayback" }
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
        let url = format!("http://web.archive.org/cdx/search/cdx?url=*.{}&output=json&fl=original&collapse=urlkey", domain);
        limiter.until_ready().await;
        let resp = client.get(&url).send().await?.error_for_status()?;
        let max_size = config.max_response_size;
        let bytes = gossan_core::read_response_limited(resp, max_size).await?;
        let mut seen = std::collections::HashSet::new();
        let domain_lower = domain.to_lowercase();

        match serde_json::from_slice::<Vec<Vec<String>>>(&bytes) {
            Ok(arr) => {
                for row in arr.iter().skip(1) {
                    if let Some(u) = row.first() {
                        if let Ok(parsed) = url::Url::parse(u) {
                            if let Some(host) = parsed.host_str() {
                                let host = host.to_lowercase();
                                if crate::is_subdomain_of(&host, &domain_lower) {
                                    seen.insert(host);
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "wayback CDX JSON parse failed; returning no subdomains");
            }
        }

        Ok(seen.into_iter().map(|d| Target::Domain(DomainTarget {
            domain: d,
            source: DiscoverySource::PassiveDns,
        })).collect())
    }
}
