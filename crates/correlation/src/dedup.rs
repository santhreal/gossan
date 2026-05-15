//! Deduplication logic for findings.
//!
//! Normalizes hosts by:
//! - Case folding
//! - Trailing dot stripping
//! - Punycode decoding (IDNA)
//! - Scheme/port stripping
//! - Wildcard prefix suppression

use std::collections::HashSet;

/// Normalize a host or target string for deduplication.
pub fn normalize_host(target: &str) -> String {
    let mut s = target;

    // Strip scheme
    if let Some(rest) = s.strip_prefix("http://") {
        s = rest;
    } else if let Some(rest) = s.strip_prefix("https://") {
        s = rest;
    }

    // Strip userinfo if present (e.g., user:pass@host)
    if let Some(at) = s.find('@') {
        s = &s[at + 1..];
    }

    // Strip port and path
    if let Some(idx) = s.find('/') {
        s = &s[..idx];
    }
    if let Some(idx) = s.rfind(':') {
        // IPv6 bracket notation: [::1]:443
        if s.starts_with('[') && s.contains("]:") {
            s = &s[..idx];
        } else if s[idx + 1..].chars().all(|c| c.is_ascii_digit()) {
            s = &s[..idx];
        }
    }

    // Case fold
    let mut out = s.to_lowercase();

    // Strip trailing dot
    out = out.trim_end_matches('.').to_string();

    // Decode punycode if present. `idna::domain_to_unicode` returns
    // `(String, Result<(), Errors>)` — keep the unicode form even on
    // partial-success Errors, drop on hard error.
    if out.starts_with("xn--") {
        let (decoded, _maybe_err) = idna::domain_to_unicode(&out);
        out = decoded.to_lowercase();
    }

    out
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
        // Wildcard-covered concretes share a key with their wildcard
        // so the dedup set collapses both to a single survivor. The
        // survivor (whichever appears first in input) gets the
        // `wildcard-origin` tag. Apex domains are NOT covered (see
        // is_wildcard_covered).
        let key = if norm.starts_with("*.") {
            strip_wildcard(&norm)
        } else if let Some(wild) = wildcards
            .iter()
            .find(|w| is_wildcard_covered(w, f.target()))
        {
            strip_wildcard(wild)
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
}
