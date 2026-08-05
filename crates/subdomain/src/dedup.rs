//! Domain deduplication with normalization.

use std::collections::HashSet;

/// Normalize a domain for deduplication.
///
/// Steps:
/// 1. Trim whitespace and trailing dot.
/// 2. Convert IDN (Unicode) to punycode via `url::Host::parse`.
/// 3. Lowercase.
pub fn normalize_domain(domain: &str) -> Option<String> {
    let trimmed = domain.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }
    match url::Host::parse(trimmed) {
        Ok(url::Host::Domain(d)) => Some(d.to_lowercase()),
        _ => Some(trimmed.to_lowercase()),
    }
}

/// Deduplicate an iterator of domain strings.
pub fn dedup_domains<I: IntoIterator<Item = String>>(domains: I) -> HashSet<String> {
    let mut seen = HashSet::new();
    for d in domains {
        if let Some(n) = normalize_domain(&d) {
            seen.insert(n);
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    #[test]
    fn normalize_lowercase() {
        assert_eq!(
            normalize_domain("API.Example.COM"),
            Some("api.example.com".to_string())
        );
    }

    #[test]
    fn normalize_trailing_dot() {
        assert_eq!(
            normalize_domain("api.example.com."),
            Some("api.example.com".to_string())
        );
    }

    #[test]
    fn normalize_punycode() {
        assert_eq!(
            normalize_domain("münchen.example.com"),
            Some("xn--mnchen-3ya.example.com".to_string())
        );
    }

    #[test]
    fn dedup_is_commutative() {
        let a = vec!["API.Example.COM".into(), "api.example.com.".into()];
        let b = vec!["api.example.com.".into(), "API.Example.COM".into()];
        assert_eq!(dedup_domains(a), dedup_domains(b));
    }

    #[test]
    fn dedup_mixed_unicode_and_ace() {
        let domains = vec![
            "münchen.example.com".into(),
            "xn--mnchen-3ya.example.com".into(),
        ];
        let deduped = dedup_domains(domains);
        assert_eq!(deduped.len(), 1);
        assert!(deduped.contains("xn--mnchen-3ya.example.com"));
    }

    #[test]
    fn dedup_exact_duplicates() {
        let domains = vec![
            "api.example.com".into(),
            "api.example.com".into(),
            "api.example.com".into(),
        ];
        let deduped = dedup_domains(domains);
        assert_eq!(deduped.len(), 1);
        assert!(deduped.contains("api.example.com"));
    }

    #[test]
    fn dedup_case_variations() {
        let domains = vec![
            "API.Example.COM".into(),
            "api.example.com".into(),
            "Api.Example.Com".into(),
        ];
        let deduped = dedup_domains(domains);
        assert_eq!(deduped.len(), 1);
        assert!(deduped.contains("api.example.com"));
    }

    #[test]
    fn dedup_trailing_dots() {
        let domains = vec![
            "api.example.com.".into(),
            "api.example.com".into(),
            "api.example.com.".into(),
        ];
        let deduped = dedup_domains(domains);
        assert_eq!(deduped.len(), 1);
        assert!(deduped.contains("api.example.com"));
    }

    #[test]
    fn dedup_subdomain_vs_root_domain() {
        let domains = vec![
            "example.com".into(),
            "api.example.com".into(),
            "www.example.com".into(),
        ];
        let deduped = dedup_domains(domains);
        // root domain and subdomains are all valid distinct targets
        assert_eq!(deduped.len(), 3);
        assert!(deduped.contains("example.com"));
        assert!(deduped.contains("api.example.com"));
        assert!(deduped.contains("www.example.com"));
    }

    #[test]
    fn normalize_empty_string() {
        assert_eq!(normalize_domain(""), None);
    }

    #[test]
    fn normalize_whitespace_only() {
        assert_eq!(normalize_domain("   "), None);
    }

    #[test]
    fn normalize_whitespace_surrounded() {
        assert_eq!(
            normalize_domain("  api.example.com  "),
            Some("api.example.com".to_string())
        );
    }

    #[test]
    fn normalize_ipv4_returns_lowercase() {
        // IP addresses are not domains, so url::Host::parse returns Ipv4
        // and we fall back to trimmed lowercase
        assert_eq!(
            normalize_domain("1.2.3.4"),
            Some("1.2.3.4".to_string())
        );
    }

    #[test]
    fn normalize_unicode_idn() {
        assert_eq!(
            normalize_domain("例え.jp"),
            Some("xn--r8jz45g.jp".to_string())
        );
    }

    #[test]
    fn dedup_empty_strings_dropped() {
        let domains = vec![
            "".to_string(),
            "  ".to_string(),
            "api.example.com".to_string(),
        ];
        let deduped = dedup_domains(domains);
        assert_eq!(deduped.len(), 1);
        assert!(deduped.contains("api.example.com"));
    }

    #[test]
    fn dedup_multiple_punycode_variants() {
        let domains = vec![
            "münchen.example.com".into(),
            "MÜNCHEN.EXAMPLE.COM.".into(),
            "xn--mnchen-3ya.example.com".into(),
            "xn--mnchen-3ya.example.com.".into(),
        ];
        let deduped = dedup_domains(domains);
        assert_eq!(deduped.len(), 1);
        assert!(deduped.contains("xn--mnchen-3ya.example.com"));
    }

    proptest! {
        /// Property: `normalize_domain` never panics.
        #[test]
        fn normalize_never_panics(domain in ".*") {
            let _ = normalize_domain(&domain);
        }

        /// Property: `normalize_domain` returns lowercase when it returns Some.
        #[test]
        fn normalize_is_lowercase(domain in ".*") {
            if let Some(n) = normalize_domain(&domain) {
                prop_assert_eq!(n.clone(), n.to_lowercase());
            }
        }

        /// Property: `dedup_domains` never panics.
        #[test]
        fn dedup_never_panics(domains in prop::collection::vec(".*", 0..50)) {
            let _ = dedup_domains(domains);
        }

        /// Property: `dedup_domains` output size is <= input size.
        #[test]
        fn dedup_never_grows(domains in prop::collection::vec(".*", 0..50)) {
            let input_len = domains.len();
            let out = dedup_domains(domains);
            prop_assert!(out.len() <= input_len);
        }

        /// Property: `normalize_domain` is idempotent for domain-like strings.
        #[test]
        fn normalize_idempotent(domain in "[a-zA-Z0-9.-]{0,128}") {
            let once = normalize_domain(&domain);
            let twice = once.as_deref().and_then(normalize_domain);
            prop_assert_eq!(once, twice);
        }
    }
}
