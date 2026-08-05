//! Passivetotal subdomain source.
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use crate::sources::{SubdomainSource, SourceRate};
use async_trait::async_trait;
use governor::DefaultDirectRateLimiter;

pub struct Passivetotal;

#[async_trait]
impl SubdomainSource for Passivetotal {
    fn name(&self) -> &'static str { "passivetotal" }
    fn requires_api_key(&self) -> bool { true }
    fn api_key_name(&self) -> &'static str { "PASSIVETOTAL_API_KEY" }
    fn rate_limit(&self) -> SourceRate { SourceRate::per_second(1) }
    fn discovery_source(&self) -> DiscoverySource { DiscoverySource::PassiveDns }

    async fn query(
        &self,
        domain: &str,
        config: &Config,
        client: &reqwest::Client,
        limiter: &DefaultDirectRateLimiter,
    ) -> anyhow::Result<Vec<Target>> {
        
        let Some(api_key) = crate::sources::get_api_key(config, "passivetotal", "PASSIVETOTAL_API_KEY") else {
            return Ok(vec![]);
        };
        let Some(email) = config.api_keys.get("passivetotal_email").cloned()
            .or_else(|| std::env::var("PASSIVETOTAL_EMAIL").ok())
        else {
            return Err(anyhow::anyhow!("PassiveTotal requires PASSIVETOTAL_EMAIL"));
        };

        let url = format!("https://api.passivetotal.org/v2/enrichment/subdomains?query={}", domain);
        limiter.until_ready().await;
        let resp = client
            .get(&url)
            .basic_auth(email, Some(api_key))
            .send()
            .await?
            .error_for_status()?;
        let max_size = config.max_response_size;
        let bytes = gossan_core::read_response_limited(resp, max_size).await?;
        let mut seen = std::collections::HashSet::new();
        let domain_lower = domain.to_lowercase();
        
        let json: serde_json::Value = serde_json::from_slice(&bytes)?;
        if let Some(arr) = json.get("subdomains").and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(v) = item.as_str() {
                    let candidate = v.trim().trim_start_matches("*.").to_lowercase();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_has_basic_auth() {
        let client = reqwest::Client::new();
        let url = format!("https://api.passivetotal.org/v2/enrichment/subdomains?query={}", "example.com");
        let req = client
            .get(&url)
            .basic_auth("user@example.com", Some("secret"))
            .build()
            .unwrap();
        let auth = req.headers().get("Authorization").unwrap().to_str().unwrap();
        assert!(auth.starts_with("Basic "));
    }
}
