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
}
