//! GodaddyCt Certificate Transparency log source.
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use crate::sources::{SubdomainSource, SourceRate};
use async_trait::async_trait;
use governor::DefaultDirectRateLimiter;

pub struct GodaddyCt;

#[async_trait]
impl SubdomainSource for GodaddyCt {
    fn name(&self) -> &'static str { "godaddy_ct" }
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
        let url = format!("https://ct.godaddy.com/logs/ct/v1/get-entries?domain={}", domain);
        limiter.until_ready().await;
        let resp = client.get(&url).send().await?;
        let max_size = config.max_response_size;
        let bytes = gossan_core::read_response_limited(resp, max_size).await?;
        let mut seen = std::collections::HashSet::new();
        let domain_lower = domain.to_lowercase();
        
        // Defensive parsing: try array of objects with name_value/subjects first
        if let Ok(arr) = serde_json::from_slice::<Vec<serde_json::Value>>(&bytes) {
            for item in arr {
                let vals: Vec<String> = if let Some(nv) = item.get("name_value").and_then(|v| v.as_str()) {
                    vec![nv.to_string()]
                } else if let Some(subs) = item.get("subjects").and_then(|v| v.as_array()) {
                    subs.iter().filter_map(|v| v.as_str().map(String::from)).collect()
                } else {
                    vec![]
                };
                for val in vals {
                    for line in val.lines() {
                        let candidate = line.trim().trim_start_matches("*.").to_lowercase();
                        if !candidate.contains('*') && crate::is_subdomain_of(&candidate, &domain_lower) {
                            seen.insert(candidate);
                        }
                    }
                }
            }
        } else if let Ok(obj) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            if let Some(data) = obj.get("data").and_then(|v| v.as_array()) {
                for item in data {
                    if let Some(nv) = item.get("name_value").and_then(|v| v.as_str()) {
                        for line in nv.lines() {
                            let candidate = line.trim().trim_start_matches("*.").to_lowercase();
                            if !candidate.contains('*') && crate::is_subdomain_of(&candidate, &domain_lower) {
                                seen.insert(candidate);
                            }
                        }
                    }
                }
            }
        }

        Ok(seen.into_iter().map(|d| Target::Domain(DomainTarget {
            domain: d,
            source: DiscoverySource::CertificateTransparency,
        })).collect())
    }
}
