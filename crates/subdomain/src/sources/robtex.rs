//! Robtex subdomain source.
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use crate::sources::{SubdomainSource, SourceRate};
use async_trait::async_trait;
use governor::DefaultDirectRateLimiter;

pub struct Robtex;

#[async_trait]
impl SubdomainSource for Robtex {
    fn name(&self) -> &'static str { "robtex" }
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
        
        let url = format!("https://freeapi.robtex.com/pdns/forward/{}", domain);
        limiter.until_ready().await;
        let resp = client.get(&url).send().await?.error_for_status()?;
        let max_size = config.max_response_size;
        let text = String::from_utf8(gossan_core::read_response_limited(resp, max_size).await?)?;
        let mut seen = std::collections::HashSet::new();
        let domain_lower = domain.to_lowercase();
        let mut ndjson_parse_errs = 0u32;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() { continue; }
            match serde_json::from_str::<serde_json::Value>(line) {
                Ok(json) => {
                    if let Some(v) = json.get("rrname").and_then(|v| v.as_str()) {
                        let candidate = v.trim().trim_end_matches('.').to_lowercase();
                        if crate::is_subdomain_of(&candidate, &domain_lower) {
                            seen.insert(candidate);
                        }
                    }
                }
                Err(e) => {
                    ndjson_parse_errs += 1;
                    if ndjson_parse_errs == 1 {
                        tracing::warn!(error = %e, source = "robtex", "NDJSON line parse failed (further errors suppressed)");
                    }
                }
            }
        }
        if ndjson_parse_errs > 1 {
            tracing::warn!(count = ndjson_parse_errs, source = "robtex", "NDJSON line parse failures");
        }
        Ok(seen.into_iter().map(|d| Target::Domain(DomainTarget {
            domain: d,
            source: DiscoverySource::PassiveDns,
        })).collect())
    }
}
