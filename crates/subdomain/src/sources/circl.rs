//! Circl subdomain source.
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use crate::sources::{SubdomainSource, SourceRate};
use async_trait::async_trait;
use governor::DefaultDirectRateLimiter;

pub struct Circl;

#[async_trait]
impl SubdomainSource for Circl {
    fn name(&self) -> &'static str { "circl" }
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
        
        let url = format!("https://www.circl.lu/pdns/query/{}", domain);
        limiter.until_ready().await;
        let resp = client.get(&url).send().await?.error_for_status()?;
        let max_size = config.max_response_size;
        let bytes = gossan_core::read_response_limited(resp, max_size).await?;
        let mut seen = std::collections::HashSet::new();
        let domain_lower = domain.to_lowercase();
        
        let text = String::from_utf8_lossy(&bytes).into_owned();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<serde_json::Value>(line.trim()) {
                Ok(val) => {
                    if let Some(name) = val.get("rrname").and_then(|v| v.as_str()) {
                        let candidate = name.trim().trim_start_matches("*.").to_lowercase();
                        if !candidate.contains('*') && crate::is_subdomain_of(&candidate, &domain_lower) {
                            seen.insert(candidate);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        line = %line.chars().take(80).collect::<String>(),
                        "circl PDNS line JSON parse failed; skipping line"
                    );
                }
            }
        }

        Ok(seen.into_iter().map(|d| Target::Domain(DomainTarget {
            domain: d,
            source: DiscoverySource::PassiveDns,
        })).collect())
    }
}
