//! Subdomain permutation engine.

use futures::StreamExt;
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

const ALL_VARIANTS: &str = include_str!("permutations.txt");
const SEPS: &[&str] = &["-", "", "."];

/// Expand permutations with wildcard-aware resolution.
pub async fn expand(
    found: &[Target],
    root_domain: &str,
    config: &Config,
    wildcard_ips: &HashSet<IpAddr>,
    resolver: &hickory_resolver::TokioAsyncResolver,
) -> anyhow::Result<Vec<Target>> {
    let known: HashSet<String> = found
        .iter()
        .filter_map(|t| t.domain().map(String::from))
        .collect();

    let candidates = generate_markov_and_dictionary_candidates(found, root_domain, &known);

    if candidates.is_empty() {
        return Ok(vec![]);
    }

    tracing::debug!(
        count = candidates.len(),
        root = root_domain,
        "permutation candidates generated via probabilistic modeling"
    );

    let resolver = Arc::new(resolver.clone());

    let targets: Vec<Target> = futures::stream::iter(candidates)
        .map(|candidate| {
            let resolver = Arc::clone(&resolver);
            let wildcards = wildcard_ips.clone();
            async move {
                let Ok(lookup) = resolver.lookup_ip(candidate.as_str()).await else {
                    return None;
                };
                if lookup.iter().any(|ip| wildcards.contains(&ip)) {
                    return None;
                }
                Some(Target::Domain(DomainTarget {
                    domain: candidate,
                    source: DiscoverySource::DnsBruteforce,
                }))
            }
        })
        .buffer_unordered(config.concurrency)
        .filter_map(|x| async move { x })
        .collect()
        .await;

    tracing::info!(found = targets.len(), root = root_domain, "permutation hits");
    Ok(targets)
}

fn tokenize(domain: &str, root_domain: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let without_root = domain
        .strip_suffix(&format!(".{}", root_domain))
        .unwrap_or(domain);

    if without_root.is_empty() {
        return tokens;
    }

    for part in without_root.split(|c| c == '.' || c == '-') {
        if part.len() >= 2 {
            let mut current = String::new();
            let mut is_num = false;

            for c in part.chars() {
                let num = c.is_ascii_digit();
                if current.is_empty() {
                    current.push(c);
                    is_num = num;
                } else if is_num == num {
                    current.push(c);
                } else {
                    if current.len() >= 2 {
                        tokens.push(current.clone());
                    }
                    current.clear();
                    current.push(c);
                    is_num = num;
                }
            }
            if current.len() >= 2 || (is_num && !current.is_empty()) {
                tokens.push(current);
            }
        } else if !part.is_empty() {
            tokens.push(part.to_string());
        }
    }
    tokens
}

fn generate_markov_and_dictionary_candidates(
    found: &[Target],
    root_domain: &str,
    known: &HashSet<String>,
) -> Vec<String> {
    let mut candidates = HashSet::new();

    let all_variants: Vec<&str> = ALL_VARIANTS
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();

    // 1. Token extraction and Transition Graph (Markov Chains)
    let mut tokens = HashSet::new();
    let mut transitions: HashMap<String, HashSet<String>> = HashMap::new();

    for t in found {
        if let Some(domain) = t.domain() {
            if domain == root_domain || !domain.ends_with(root_domain) {
                continue;
            }
            let tks = tokenize(domain, root_domain);
            for t in &tks {
                tokens.insert(t.clone());
            }

            for i in 0..tks.len().saturating_sub(1) {
                transitions
                    .entry(tks[i].clone())
                    .or_default()
                    .insert(tks[i + 1].clone());
            }
        }
    }

    // 2. Synthesize Markov Chain Candidates
    for start_node in &tokens {
        if let Some(next_nodes) = transitions.get(start_node) {
            for next in next_nodes {
                for sep in SEPS {
                    candidates.insert(format!("{}{}{}.{}", start_node, sep, next, root_domain));
                    candidates.insert(format!("{}{}{}.{}", next, sep, start_node, root_domain));
                }
            }
        }
    }

    // 3. Classical Dictionary Pollination
    for prefix in &tokens {
        for variant in &all_variants {
            for sep in SEPS {
                candidates.insert(format!("{}{}{}.{}", prefix, sep, variant, root_domain));
                candidates.insert(format!("{}{}{}.{}", variant, sep, prefix, root_domain));
            }
        }
        for i in 1..=5 {
            candidates.insert(format!("{}{}.{}", prefix, i, root_domain));
            candidates.insert(format!("{}-{}.{}", prefix, i, root_domain));
        }
    }

    candidates
        .into_iter()
        .filter(|c| !known.contains(c))
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
    fn tokenize_extracts_labels_and_numeric_boundaries() {
        let tks = tokenize("dev-api1.example.com", "example.com");
        assert!(tks.contains(&"dev".to_string()));
        assert!(tks.contains(&"api".to_string()));
        assert!(tks.contains(&"1".to_string()));
    }

    #[test]
    fn markov_generation_learns_transitions() {
        let found = vec![domain_target("prod-db.example.com")];
        let known = HashSet::new();
        let candidates = generate_markov_and_dictionary_candidates(&found, "example.com", &known);
        // candidates is Vec<String>; Vec<T>::contains takes &T (no
        // Borrow magic), so the assertion targets must match the
        // element type. Using `iter().any(|c| c == lit)` keeps the
        // expectation literal-readable without per-call to_string()
        // boilerplate.
        assert!(candidates.iter().any(|c| c == "prod-db.example.com"));
        assert!(candidates.iter().any(|c| c == "db-prod.example.com"));
        assert!(candidates.iter().any(|c| c == "proddb.example.com"));
    }

    #[test]
    fn dictionary_pollination() {
        let found = vec![domain_target("auth.example.com")];
        let known = HashSet::new();
        let candidates = generate_markov_and_dictionary_candidates(&found, "example.com", &known);
        assert!(candidates.iter().any(|c| c == "auth1.example.com"));
        assert!(candidates.iter().any(|c| c == "auth-2.example.com"));
    }
}
