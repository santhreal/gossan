//! Subdomain permutation engine.
//!
//! Takes the set of *already confirmed* subdomains and generates intelligent
//! mutations. Unlike wordlist bruteforce, permutations are seeded by what
//! was actually found — so they match the target's real naming conventions.
//!
//! Example: found `api.target.com` → probe:
//!   api-v2, api-dev, api-staging, api-old, api-internal, api-beta, …
//!   dev-api, staging-api, old-api, internal-api, …
//!
//! This reaches assets that passive CT/Wayback enumeration misses because
//! they were never exposed to the public internet (internal staging, shadow APIs).

use futures::StreamExt;
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use std::collections::HashSet;
use std::sync::Arc;

use crate::build_resolver;

// Load 60+ expanded permutation terms at compile time
const ALL_VARIANTS: &str = include_str!("permutations.txt");
const SEPS: &[&str] = &["-", ""];

pub async fn expand(
    found: &[Target],
    root_domain: &str,
    config: &Config,
) -> anyhow::Result<Vec<Target>> {
    let prefixes = collect_prefixes(found, root_domain);

    if prefixes.is_empty() {
        return Ok(vec![]);
    }

    // Already-known domains to avoid re-emitting
    let known: HashSet<String> = found
        .iter()
        .filter_map(|t| t.domain().map(String::from))
        .collect();

    let candidates = build_candidates(&prefixes, root_domain, &known);

    if candidates.is_empty() {
        return Ok(vec![]);
    }

    tracing::debug!(
        count = candidates.len(),
        root = root_domain,
        "permutation candidates"
    );

    let resolver = Arc::new(build_resolver(config)?);

    // Resolve all candidates concurrently
    let targets: Vec<Target> = futures::stream::iter(candidates)
        .map(|candidate| {
            let resolver = Arc::clone(&resolver);
            async move {
                resolver.lookup_ip(candidate.as_str()).await.ok().map(|_| {
                    Target::Domain(DomainTarget {
                        domain: candidate,
                        source: DiscoverySource::DnsBruteforce,
                    })
                })
            }
        })
        .buffer_unordered(config.concurrency)
        .filter_map(|x| async move { x })
        .collect()
        .await;

    tracing::info!(
        found = targets.len(),
        root = root_domain,
        "permutation hits"
    );
    Ok(targets)
}

fn collect_prefixes(found: &[Target], root_domain: &str) -> HashSet<String> {
    let mut prefixes: HashSet<String> = HashSet::new();

    for t in found {
        let Some(domain) = t.domain() else { continue };
        if domain == root_domain || !domain.ends_with(root_domain) {
            continue;
        }

        let without_root = domain
            .strip_suffix(&format!(".{}", root_domain))
            .unwrap_or(domain);

        if without_root.is_empty() {
            continue;
        }

        prefixes.insert(without_root.to_string());
        for part in without_root.split('-').filter(|p| p.len() >= 2) {
            prefixes.insert(part.to_string());
        }
    }

    prefixes
}

fn build_candidates(
    prefixes: &HashSet<String>,
    root_domain: &str,
    known: &HashSet<String>,
) -> Vec<String> {
    let mut candidates: HashSet<String> = HashSet::new();
    let all_variants: Vec<&str> = ALL_VARIANTS
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();

    for prefix in prefixes {
        for variant in &all_variants {
            for sep in SEPS {
                candidates.insert(format!("{}{}{}.{}", prefix, sep, variant, root_domain));
                candidates.insert(format!("{}{}{}.{}", variant, sep, prefix, root_domain));
            }
        }
    }

    candidates
        .into_iter()
        .filter(|candidate| !known.contains(candidate))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::{DiscoverySource, DomainTarget};

    fn domain_target(domain: &str) -> Target {
        Target::Domain(DomainTarget {
            domain: domain.into(),
            source: DiscoverySource::Seed,
        })
    }

    #[test]
    fn collect_prefixes_extracts_full_label_and_dash_components() {
        let found = vec![domain_target("dev-api.example.com")];
        let prefixes = collect_prefixes(&found, "example.com");

        assert!(prefixes.contains("dev-api"));
        assert!(prefixes.contains("dev"));
        assert!(prefixes.contains("api"));
    }

    #[test]
    fn collect_prefixes_ignores_root_domain_and_out_of_scope_domains() {
        let found = vec![
            domain_target("example.com"),
            domain_target("api.example.org"),
            domain_target("api.example.com"),
        ];
        let prefixes = collect_prefixes(&found, "example.com");

        assert_eq!(prefixes.len(), 1);
        assert!(prefixes.contains("api"));
    }

    #[test]
    fn collect_prefixes_handles_multi_label_subdomains() {
        let found = vec![domain_target("a.b.example.com")];
        let prefixes = collect_prefixes(&found, "example.com");
        assert!(prefixes.contains("a.b"));
    }

    #[test]
    fn collect_prefixes_deduplicates_duplicates() {
        let found = vec![
            domain_target("api.example.com"),
            domain_target("api.example.com"),
        ];
        let prefixes = collect_prefixes(&found, "example.com");
        assert_eq!(prefixes.len(), 1);
        assert!(prefixes.contains("api"));
    }

    #[test]
    fn build_candidates_generates_prefix_suffix_and_suffix_prefix_forms() {
        let prefixes = HashSet::from([String::from("api")]);
        let candidates = build_candidates(&prefixes, "example.com", &HashSet::new());

        assert!(candidates.iter().any(|c| c == "api-dev.example.com"));
        assert!(candidates.iter().any(|c| c == "dev-api.example.com"));
        assert!(candidates.iter().any(|c| c == "apidev.example.com"));
        assert!(candidates.iter().any(|c| c == "devapi.example.com"));
    }

    #[test]
    fn build_candidates_filters_known_domains() {
        let prefixes = HashSet::from([String::from("api")]);
        let known = HashSet::from([String::from("api-dev.example.com")]);
        let candidates = build_candidates(&prefixes, "example.com", &known);

        assert!(!candidates.iter().any(|c| c == "api-dev.example.com"));
        assert!(candidates.iter().any(|c| c == "dev-api.example.com"));
    }

    #[test]
    fn build_candidates_deduplicates_results() {
        let prefixes = HashSet::from([String::from("api"), String::from("api")]);
        let candidates = build_candidates(&prefixes, "example.com", &HashSet::new());

        let unique_count = candidates.iter().collect::<HashSet<_>>().len();
        assert_eq!(unique_count, candidates.len());
    }
}
