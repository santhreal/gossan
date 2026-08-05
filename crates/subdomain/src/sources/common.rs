//! Shared helpers for subdomain sources.

use std::collections::HashSet;

use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use governor::DefaultDirectRateLimiter;

/// Retrieve an API key from config or environment.
pub fn get_api_key(config: &Config, source_name: &str, env_name: &str) -> Option<String> {
    config
        .api_keys
        .get(source_name)
        .cloned()
        .or_else(|| std::env::var(env_name).ok())
}

/// Shared `get-entries`-style Certificate Transparency query + parse used by
/// the per-CA CT sources (Amazon, Apple, Cloudflare, DigiCert, Entrust,
/// Facebook, GoDaddy, Google, IdenTrust, Sectigo), which differ only in
/// their endpoint URL (this is the one place that body lived in 10 copies).
///
/// Defensively handles the response shapes these endpoints return in
/// practice: a top-level array of objects carrying either `name_value`
/// (crt.sh-style) or a `subjects` array, and an object wrapping a `data`
/// array of `{name_value}`. Names are normalized (trimmed, `*.`-stripped,
/// lowercased, wildcard-dropped) and filtered to strict subdomains of
/// `domain`. A body that matches none of the shapes yields no targets
/// rather than erroring, so one flaky/again-shaped CT log can't fail a run.
pub async fn ct_get_entries(
    domain: &str,
    url: &str,
    config: &Config,
    client: &reqwest::Client,
    limiter: &DefaultDirectRateLimiter,
) -> anyhow::Result<Vec<Target>> {
    limiter.until_ready().await;
    let resp = client.get(url).send().await?.error_for_status()?;
    let bytes = gossan_core::read_response_limited(resp, config.max_response_size).await?;

    let mut seen = HashSet::new();
    let domain_lower = domain.to_lowercase();

    if let Ok(arr) = serde_json::from_slice::<Vec<serde_json::Value>>(&bytes) {
        for item in arr {
            if let Some(nv) = item.get("name_value").and_then(|v| v.as_str()) {
                collect_subdomains(nv, &domain_lower, &mut seen);
            } else if let Some(subs) = item.get("subjects").and_then(|v| v.as_array()) {
                for s in subs.iter().filter_map(|v| v.as_str()) {
                    collect_subdomains(s, &domain_lower, &mut seen);
                }
            }
        }
    } else if let Ok(obj) = serde_json::from_slice::<serde_json::Value>(&bytes) {
        if let Some(data) = obj.get("data").and_then(|v| v.as_array()) {
            for item in data {
                if let Some(nv) = item.get("name_value").and_then(|v| v.as_str()) {
                    collect_subdomains(nv, &domain_lower, &mut seen);
                }
            }
        }
    } else {
        tracing::warn!(
            url = %url,
            bytes = bytes.len(),
            "CT JSON body was neither array nor object; returning no subdomains"
        );
    }

    Ok(seen
        .into_iter()
        .map(|d| {
            Target::Domain(DomainTarget {
                domain: d,
                source: DiscoverySource::CertificateTransparency,
            })
        })
        .collect())
}

/// Split a newline-joined CN/SAN value, normalize each host (trim, strip a
/// leading `*.` wildcard, lowercase, drop residual wildcards) and insert
/// those that are strict subdomains of `domain_lower`.
fn collect_subdomains(raw: &str, domain_lower: &str, seen: &mut HashSet<String>) {
    for line in raw.lines() {
        let candidate = line.trim().trim_start_matches("*.").to_lowercase();
        if !candidate.contains('*') && crate::is_subdomain_of(&candidate, domain_lower) {
            seen.insert(candidate);
        }
    }
}
