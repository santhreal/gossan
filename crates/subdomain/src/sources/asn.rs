
//! ASN-pivot subdomain source.
//!
//! Resolves the target domain to an IP, looks up the owning ASN via
//! HackerTarget's free ASN-lookup API, then queries HackerTarget's
//! reverse-IP/ASN endpoint to enumerate hosts sharing the same AS.
//! Discovered subdomains of the seed domain are returned as targets.
//!
//! No API key required; rate-limited to 1 req/s to respect the free tier.

use crate::sources::{SourceRate, SubdomainSource};
use async_trait::async_trait;
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use governor::DefaultDirectRateLimiter;
use std::collections::HashSet;

pub struct Asn;

#[async_trait]
impl SubdomainSource for Asn {
    fn name(&self) -> &'static str {
        "asn"
    }
    fn requires_api_key(&self) -> bool {
        false
    }
    fn api_key_name(&self) -> &'static str {
        ""
    }
    fn rate_limit(&self) -> SourceRate {
        SourceRate::per_second(1)
    }
    fn discovery_source(&self) -> DiscoverySource {
        DiscoverySource::Asn
    }

    async fn query(
        &self,
        domain: &str,
        config: &Config,
        client: &reqwest::Client,
        limiter: &DefaultDirectRateLimiter,
    ) -> anyhow::Result<Vec<Target>> {
        let domain_lower = domain.to_lowercase();

        // Step 1 (look up ASN for the domain via HackerTarget (free, no key)).
        let asn_url = format!("https://api.hackertarget.com/aslookup/?q={}", domain_lower);
        limiter.until_ready().await;
        let resp = client.get(&asn_url).send().await?.error_for_status()?;
        let max_size = config.max_response_size;
        let bytes = gossan_core::read_response_limited(resp, max_size).await?;
        let text = String::from_utf8_lossy(&bytes);

        // Response format: `"IP","AS<number>","<org>","<country>"`
        // We only need the AS number from the second comma-delimited field.
        let asn = text
            .lines()
            .next()
            .and_then(|line| {
                let mut fields = line.splitn(4, ',');
                fields.next(); // skip IP field
                fields
                    .next()
                    .map(|f| f.trim().trim_matches('"').to_string())
            })
            .filter(|s| s.starts_with("AS") || s.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false));

        let Some(asn) = asn else {
            // No resolvable ASN → graceful empty result.
            return Ok(vec![]);
        };

        // Normalise: strip the "AS" prefix so we pass a bare number.
        let asn_number = asn.trim_start_matches("AS").trim_start_matches("as");

        // Step 2 (enumerate all hosts in the same AS via HackerTarget).
        let hosts_url = format!(
            "https://api.hackertarget.com/aslookup/?q=AS{}",
            asn_number
        );
        limiter.until_ready().await;
        let resp2 = client.get(&hosts_url).send().await?.error_for_status()?;
        let bytes2 = gossan_core::read_response_limited(resp2, max_size).await?;
        let text2 = String::from_utf8_lossy(&bytes2);

        let mut seen: HashSet<String> = HashSet::new();
        for line in text2.lines() {
            let candidate = line
                .trim()
                .trim_start_matches("*.")
                .to_lowercase();
            if !candidate.is_empty()
                && !candidate.contains('*')
                && !candidate.contains(' ')
                && crate::is_subdomain_of(&candidate, &domain_lower)
            {
                seen.insert(candidate);
            }
        }

        Ok(seen
            .into_iter()
            .map(|d| {
                Target::Domain(DomainTarget {
                    domain: d,
                    source: DiscoverySource::Asn,
                })
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asn_source_metadata() {
        let src = Asn;
        assert_eq!(src.name(), "asn");
        assert!(!src.requires_api_key());
        assert_eq!(src.api_key_name(), "");
        assert!(matches!(src.discovery_source(), DiscoverySource::Asn));
    }

    /// The source must not panic on empty / garbage API responses.
    #[tokio::test]
    async fn asn_query_graceful_on_bad_asn_response() {
        // We can't call the live API in unit tests, but we can prove the
        // None-path (no ASN found) returns an empty vec without panicking.
        // The logic below mirrors what `query` does after the first HTTP call.
        let text = "error check your query"; // HackerTarget error response
        let asn = text
            .lines()
            .next()
            .and_then(|line| {
                let mut fields = line.splitn(4, ',');
                fields.next();
                fields
                    .next()
                    .map(|f| f.trim().trim_matches('"').to_string())
            })
            .filter(|s| {
                s.starts_with("AS")
                    || s.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false)
            });
        assert!(asn.is_none(), "error text must not parse as an ASN");
    }

    #[test]
    fn asn_query_parses_valid_response_format() {
        // Simulate a valid HackerTarget ASN-lookup response line.
        let line = r#""93.184.216.34","AS15133","MCI Communications Services Inc","US""#;
        let asn = line.splitn(4, ',').nth(1).map(|f| f.trim().trim_matches('"').to_string());
        assert_eq!(asn.as_deref(), Some("AS15133"));

        let asn_number = asn.as_deref().unwrap_or("").trim_start_matches("AS");
        assert_eq!(asn_number, "15133");
    }

    #[test]
    fn asn_source_filters_non_subdomain_hosts() {
        // Only subdomains of the seed domain should pass the filter.
        let seed = "example.com";
        let candidates = vec![
            "api.example.com",         // subdomain → keep
            "example.com",             // root → not a subdomain
            "evil.com",                // different domain → drop
            "*.example.com",           // wildcard → drop
            "  ",                      // whitespace → drop
            "sub.api.example.com",     // deep subdomain → keep
        ];
        let filtered: Vec<&str> = candidates
            .iter()
            .filter(|&&c| {
                let candidate = c.trim().trim_start_matches("*.").to_lowercase();
                !candidate.is_empty()
                    && !candidate.contains('*')
                    && !candidate.contains(' ')
                    && crate::is_subdomain_of(&candidate, seed)
            })
            .copied()
            .collect();
        assert!(filtered.contains(&"api.example.com"));
        assert!(filtered.contains(&"sub.api.example.com"));
        assert!(!filtered.contains(&"example.com"));
        assert!(!filtered.contains(&"evil.com"));
        assert!(!filtered.contains(&"*.example.com"));
    }
}
