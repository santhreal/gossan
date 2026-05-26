//! Canonical finding deduplication for gossan and downstream
//! consumers.
//!
//! Two copies of this module used to live under
//! `gossan::correlation::dedup` and `gossan::graph::correlation::dedup`,
//! and they had diverged on a subtle but security-critical point:
//! how the wildcard bucket is keyed. The wildcard `*.example.com`
//! must collapse with its *covered* subdomains (`sub.example.com`,
//! `deep.b.example.com`) but must NOT collapse with the *apex*
//! (`example.com`) because the apex is not wildcard-covered per
//! RFC 4592 § 4.2.
//!
//! The original `correlation` copy keyed the wildcard bucket on the
//! stripped parent (`example.com`), which collided with the apex
//! finding and silently dropped it. The `graph::correlation` copy
//! later fixed this by keying on the full wildcard form
//! (`*.example.com`). This module keeps that fix as the single
//! source of truth and ships the apex-RCE adversarial regression
//! test alongside it so the bug cannot reappear.
//!
//! `normalize_host` is delegated to
//! [`crate::domain::normalize_host`], which is the canonical
//! normaliser (scheme strip, port strip, IPv6 brackets, trailing
//! dot, case fold, punycode decode). The dedup wrapper here adds
//! only the wildcard / Finding-builder logic on top.

use std::collections::HashSet;

/// Normalize a host or target string for deduplication.
///
/// Thin delegate to [`crate::domain::normalize_host`] so all gossan
/// dedup paths share the same canonical normaliser.
pub fn normalize_host(target: &str) -> String {
    crate::domain::normalize_host(target)
}

/// Strip wildcard prefix for deduplication.
pub fn strip_wildcard(host: &str) -> String {
    host.trim_start_matches("*.").to_string()
}

/// Check whether a host is covered by a wildcard record.
///
/// A wildcard `*.example.com` covers `sub.example.com` and any
/// deeper subdomain (`a.b.example.com`) but does NOT cover the apex
/// `example.com` — RFC 4592 § 4.2 / common-DNS interpretation.
pub fn is_wildcard_covered(wildcard: &str, host: &str) -> bool {
    let norm_wild = normalize_host(wildcard);
    let norm_host = normalize_host(host);
    if let Some(suffix) = norm_wild.strip_prefix("*.") {
        norm_host.ends_with(&format!(".{suffix}"))
    } else {
        false
    }
}

/// Deduplicate a list of findings by normalized target.
///
/// `Finding`'s tag list is `Arc<str>`-backed and intentionally
/// immutable post-construction (cache-safety contract). When a
/// finding is covered by a wildcard from elsewhere in the input,
/// we rebuild via `Finding::builder` to attach the
/// `wildcard-origin` tag rather than mutate in place.
pub fn dedup_findings(findings: &[secfinding::Finding]) -> Vec<secfinding::Finding> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();

    // First pass: collect all wildcard signals.
    let wildcards: Vec<String> = findings
        .iter()
        .filter_map(|f| {
            let norm = normalize_host(f.target());
            if norm.starts_with("*.") {
                Some(norm)
            } else {
                None
            }
        })
        .collect();

    for f in findings {
        let norm = normalize_host(f.target());
        // Bucket key. The wildcard and its covered concretes share a
        // key so they collapse to one survivor. That key MUST be the
        // wildcard form (`*.example.com`) and NOT the stripped parent
        // (`example.com`): a real host can never normalise to a
        // leading `*.`, but the apex `example.com` normalises to
        // exactly `example.com`. Keying the wildcard bucket on the
        // stripped parent therefore collided with the apex host and
        // silently dropped a distinct apex finding (e.g. a Critical
        // RCE on the apex) — even though `is_wildcard_covered`
        // correctly reports the apex as NOT covered.
        let key = if norm.starts_with("*.") {
            norm.clone()
        } else if let Some(wild) = wildcards
            .iter()
            .find(|w| is_wildcard_covered(w, f.target()))
        {
            wild.clone()
        } else {
            norm.clone()
        };

        if seen.insert(key.clone()) {
            let needs_tag = wildcards.iter().any(|w| is_wildcard_covered(w, f.target()))
                && !f.tags().iter().any(|t| t.as_ref() == "wildcard-origin");
            if needs_tag {
                if let Ok(rebuilt) =
                    secfinding::Finding::builder(f.scanner(), f.target(), f.severity())
                        .title(f.title())
                        .detail(f.detail())
                        .add_tags(f.tags().iter().map(|t| t.to_string()))
                        .tag("wildcard-origin")
                        .build()
                {
                    out.push(rebuilt);
                    continue;
                }
            }
            out.push(f.clone());
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_schemes() {
        assert_eq!(normalize_host("http://example.com"), "example.com");
        assert_eq!(normalize_host("https://example.com"), "example.com");
    }

    #[test]
    fn normalize_strips_ports() {
        assert_eq!(normalize_host("example.com:443"), "example.com");
        assert_eq!(normalize_host("1.2.3.4:8080"), "1.2.3.4");
    }

    #[test]
    fn normalize_strips_trailing_dot() {
        assert_eq!(normalize_host("example.com."), "example.com");
    }

    #[test]
    fn normalize_case_folds() {
        assert_eq!(normalize_host("EXAMPLE.COM"), "example.com");
    }

    #[test]
    fn normalize_ipv6_brackets() {
        assert_eq!(normalize_host("[::1]:443"), "[::1]");
    }

    #[test]
    fn wildcard_coverage() {
        assert!(is_wildcard_covered("*.example.com", "sub.example.com"));
        assert!(!is_wildcard_covered("*.example.com", "example.com"));
        assert!(!is_wildcard_covered("example.com", "sub.example.com"));
    }

    #[test]
    fn dedup_associative_commutative() {
        let f1 = secfinding::Finding::new(
            "s",
            "https://Example.COM:443/",
            secfinding::Severity::Info,
            "t",
            "",
        )
        .unwrap();
        let f2 = secfinding::Finding::new(
            "s",
            "http://example.com.",
            secfinding::Severity::Info,
            "t",
            "",
        )
        .unwrap();
        let deduped = dedup_findings(&[f1.clone(), f2.clone()]);
        assert_eq!(deduped.len(), 1);
        let deduped2 = dedup_findings(&[f2, f1]);
        assert_eq!(deduped2.len(), 1);
    }

    /// ADVERSARIAL: a wildcard-DNS finding must NOT swallow a distinct
    /// finding on the *apex* host. The apex is explicitly not
    /// wildcard-covered (RFC 4592); pre-fix the wildcard's stripped key
    /// ("example.com") collided with the apex host's key and silently
    /// dropped the apex finding — a false negative that could hide a
    /// Critical apex RCE. The test runs both orderings to prove the
    /// fix is independent of input order.
    #[test]
    fn dedup_does_not_collapse_apex_into_wildcard() {
        let wildcard = secfinding::Finding::new(
            "dns",
            "*.example.com",
            secfinding::Severity::Info,
            "Wildcard DNS record",
            "",
        )
        .unwrap();
        let apex = secfinding::Finding::new(
            "web",
            "example.com",
            secfinding::Severity::Critical,
            "RCE on apex host",
            "",
        )
        .unwrap();

        for input in [
            vec![wildcard.clone(), apex.clone()],
            vec![apex.clone(), wildcard.clone()],
        ] {
            let deduped = dedup_findings(&input);
            assert_eq!(
                deduped.len(),
                2,
                "apex finding was wrongly deduplicated against the wildcard"
            );
            assert!(
                deduped.iter().any(|f| f.title() == "RCE on apex host"),
                "the distinct apex Critical finding was silently dropped"
            );
        }
    }

    /// PROVING (regression twin): the wildcard and its *covered*
    /// subdomains still collapse to one survivor — the fix only
    /// untangled the apex, it did not disable wildcard collapsing.
    #[test]
    fn dedup_still_collapses_wildcard_and_covered_subdomains() {
        let wildcard =
            secfinding::Finding::new("dns", "*.example.com", secfinding::Severity::Info, "t", "")
                .unwrap();
        let sub_a = secfinding::Finding::new(
            "web",
            "a.example.com",
            secfinding::Severity::Info,
            "t",
            "",
        )
        .unwrap();
        let sub_b = secfinding::Finding::new(
            "web",
            "deep.b.example.com",
            secfinding::Severity::Info,
            "t",
            "",
        )
        .unwrap();
        let deduped = dedup_findings(&[wildcard, sub_a, sub_b]);
        assert_eq!(
            deduped.len(),
            1,
            "wildcard + covered subdomains must collapse to a single survivor"
        );
    }

    #[test]
    fn dedup_tags_wildcard_origin() {
        let wildcard =
            secfinding::Finding::new("s", "*.example.com", secfinding::Severity::Info, "t", "")
                .unwrap();
        let concrete =
            secfinding::Finding::new("s", "sub.example.com", secfinding::Severity::Info, "t", "")
                .unwrap();
        let deduped = dedup_findings(&[wildcard, concrete]);
        assert_eq!(deduped.len(), 1);
        assert!(deduped[0]
            .tags()
            .iter()
            .any(|t| t.as_ref() == "wildcard-origin"));
    }

    /// `dedup_tags_wildcard_origin` already proves the survivor of a
    /// wildcard collapse picks up the tag. This second case proves
    /// the tag is *not* duplicated when the survivor itself was
    /// originally the wildcard finding (which already carries the
    /// tag in some pipelines) — i.e. we don't get `wildcard-origin`
    /// twice and we don't strip an existing tag.
    #[test]
    fn dedup_does_not_double_tag_wildcard_origin() {
        let pre_tagged = secfinding::Finding::builder(
            "s",
            "*.example.com",
            secfinding::Severity::Info,
        )
        .title("t")
        .detail("")
        .tag("wildcard-origin")
        .build()
        .unwrap();
        let concrete =
            secfinding::Finding::new("s", "sub.example.com", secfinding::Severity::Info, "t", "")
                .unwrap();
        let deduped = dedup_findings(&[pre_tagged, concrete]);
        assert_eq!(deduped.len(), 1);
        let wildcard_tag_count = deduped[0]
            .tags()
            .iter()
            .filter(|t| t.as_ref() == "wildcard-origin")
            .count();
        assert_eq!(
            wildcard_tag_count, 1,
            "wildcard-origin tag must appear at most once"
        );
    }

    /// Empty input must produce empty output without panicking and
    /// without paying for an allocation that survives the call.
    #[test]
    fn dedup_empty_input_is_empty_output() {
        let deduped = dedup_findings(&[]);
        assert!(deduped.is_empty());
    }

    /// Findings whose targets differ only by trailing slash, scheme,
    /// or trailing dot are the same host and must collapse to one
    /// survivor. This pins normalisation behaviour through the dedup
    /// path (not just through `normalize_host` alone).
    #[test]
    fn dedup_collapses_url_form_variants_of_same_host() {
        let a = secfinding::Finding::new(
            "s",
            "https://example.com/",
            secfinding::Severity::Info,
            "t",
            "",
        )
        .unwrap();
        let b = secfinding::Finding::new(
            "s",
            "http://example.com",
            secfinding::Severity::Info,
            "t",
            "",
        )
        .unwrap();
        let c = secfinding::Finding::new(
            "s",
            "https://EXAMPLE.com.:443/",
            secfinding::Severity::Info,
            "t",
            "",
        )
        .unwrap();
        let deduped = dedup_findings(&[a, b, c]);
        assert_eq!(
            deduped.len(),
            1,
            "three URL forms of the same host must collapse to one survivor"
        );
    }
}
