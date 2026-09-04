//! Utility helpers for correlation rule evaluation.
//!
//! `normalize_host` delegates to the single canonical implementation in
//! [`gossan_core::domain`]. The previous copy was a hand-rolled scheme/
//! port/path stripper that did NOT lowercase, did NOT handle trailing
//! dots, did NOT handle IPv6 brackets, and silently diverged from the
//! `gossan_core::dedup::normalize_host` path already in use by
//! `gossan_graph::correlation::utils`. Two separate normalisers in two
//! correlation engines is a latent false-positive/-negative time-bomb
//! every time a rule clusters by "same host".

/// Normalise a finding target for cross-host clustering.
///
/// Delegates to `gossan_core::domain::normalize_host`: strips scheme,
/// port, trailing dot, lowercases, removes IPv6 brackets. Consistent
/// with `gossan_core::dedup` and `gossan_graph::correlation::utils`.
pub(crate) fn normalize_host(target: &str) -> String {
    gossan_core::domain::normalize_host(target)
}

/// Coarse "registrable parent" heuristic (last two labels).
/// Mirrors the helper in `gossan_graph::correlation::rules::ssrf_internal`
/// (now the only definition; was previously re-declared inline there).
/// Good enough for the same-blast-radius check; a full public-suffix-list
/// would be more precise but pulls in extra crate weight.
pub(crate) fn parent_domain(host: &str) -> String {
    let host = normalize_host(host);
    // Bare IPs are their own correlation key; never split "1.2.3.4" into "3.4".
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<std::net::IpAddr>().is_ok() {
        return host;
    }
    // Prefer the Mozilla PSL registrable domain when available so
    // example.co.uk and attacker.co.uk do not false-correlate on "co.uk".
    if let Some(reg) = gossan_core::domain::registrable(&host) {
        return reg;
    }
    let labels: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
    if labels.len() < 2 {
        return host;
    }
    labels[labels.len() - 2..].join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── normalize_host ───────────────────────────────────────────────────

    #[test]
    fn normalize_host_strips_https_scheme() {
        assert_eq!(normalize_host("https://example.com"), "example.com");
    }

    #[test]
    fn normalize_host_strips_http_scheme() {
        assert_eq!(normalize_host("http://example.com"), "example.com");
    }

    #[test]
    fn normalize_host_strips_port() {
        assert_eq!(normalize_host("example.com:443"), "example.com");
    }

    #[test]
    fn normalize_host_strips_scheme_and_port() {
        assert_eq!(normalize_host("https://example.com:8443"), "example.com");
    }

    #[test]
    fn normalize_host_lowercases() {
        assert_eq!(normalize_host("EXAMPLE.COM"), "example.com");
    }

    #[test]
    fn normalize_host_mixed_case_with_scheme() {
        assert_eq!(normalize_host("https://EXAMPLE.COM"), "example.com");
    }

    #[test]
    fn normalize_host_strips_trailing_dot() {
        // Fully-qualified domain names end with '.'; normaliser must strip it.
        assert_eq!(normalize_host("example.com."), "example.com");
    }

    #[test]
    fn normalize_host_plain_hostname_unchanged() {
        assert_eq!(normalize_host("example.com"), "example.com");
    }

    #[test]
    fn parent_domain_returns_ip_unchanged() {
        assert_eq!(parent_domain("1.2.3.4"), "1.2.3.4");
        assert_eq!(parent_domain("https://1.2.3.4:443/x"), "1.2.3.4");
    }

    #[test]
    fn parent_domain_uses_psl_for_multipart_tld() {
        assert_eq!(parent_domain("shop.example.co.uk"), "example.co.uk");
        assert_ne!(parent_domain("shop.example.co.uk"), "co.uk");
    }

    #[test]
    fn normalize_host_empty_string_does_not_panic() {
        // Should not panic (result may be empty or bare empty string).
        let _ = normalize_host("");
    }

    #[test]
    fn normalize_host_ipv4_preserved() {
        assert_eq!(normalize_host("1.2.3.4"), "1.2.3.4");
    }

    #[test]
    fn normalize_host_ipv4_with_port_stripped() {
        assert_eq!(normalize_host("1.2.3.4:8080"), "1.2.3.4");
    }

    #[test]
    fn normalize_host_with_path_strips_path() {
        // Paths after the host must not leak into the normalised value.
        let result = normalize_host("https://example.com/some/path");
        assert!(!result.contains('/'), "path must be stripped: got {result:?}");
        assert!(result.contains("example.com"), "host must be preserved: got {result:?}");
    }

    #[test]
    fn normalize_host_consistent_on_repeat_calls() {
        // Anti-rig: same input always produces same output (no random salting).
        let a = normalize_host("https://Example.COM:443/path");
        let b = normalize_host("https://Example.COM:443/path");
        assert_eq!(a, b);
    }

    #[test]
    fn normalize_host_subdomain_preserved() {
        assert_eq!(normalize_host("sub.example.com"), "sub.example.com");
    }

    #[test]
    fn normalize_host_deep_subdomain_preserved() {
        assert_eq!(normalize_host("a.b.c.example.com"), "a.b.c.example.com");
    }

    // ── parent_domain ────────────────────────────────────────────────────

    #[test]
    fn parent_domain_two_labels() {
        assert_eq!(parent_domain("example.com"), "example.com");
    }

    #[test]
    fn parent_domain_subdomain() {
        assert_eq!(parent_domain("sub.example.com"), "example.com");
    }

    #[test]
    fn parent_domain_deep_subdomain() {
        assert_eq!(parent_domain("a.b.c.example.com"), "example.com");
    }

    #[test]
    fn parent_domain_single_label_returns_as_is() {
        assert_eq!(parent_domain("localhost"), "localhost");
    }

    #[test]
    fn parent_domain_empty_string_does_not_panic() {
        let _ = parent_domain("");
    }

    #[test]
    fn parent_domain_only_dots_does_not_panic() {
        // All labels empty after filter (should return the original string).
        let result = parent_domain("...");
        // Must not panic; result value is implementation-defined.
        let _ = result;
    }

    #[test]
    fn parent_domain_trailing_dot_handled() {
        // Trailing dot produces an empty label after split; filter removes it.
        // "example.com." has labels ["example", "com"] after filtering empty strings.
        let result = parent_domain("example.com.");
        assert_eq!(result, "example.com");
    }

    #[test]
    fn parent_domain_consistent_on_same_host() {
        // Anti-rig: deterministic per call.
        let a = parent_domain("sub.example.com");
        let b = parent_domain("sub.example.com");
        assert_eq!(a, b);
    }

    #[test]
    fn parent_domain_different_parents_not_equal() {
        // Two subdomains on different registrable parents must not map to the same parent.
        let p1 = parent_domain("api.example.com");
        let p2 = parent_domain("api.attacker.com");
        assert_ne!(p1, p2);
    }

    #[test]
    fn parent_domain_siblings_share_parent() {
        // Sibling subdomains share the same registrable parent.
        let p1 = parent_domain("api.example.com");
        let p2 = parent_domain("www.example.com");
        assert_eq!(p1, p2);
    }

    #[test]
    fn parent_domain_ipv4_returns_ip_unchanged() {
        // An IP address must be its own correlation key, not split into
        // the last two octets.
        let result = parent_domain("1.2.3.4");
        assert_eq!(result, "1.2.3.4");
    }

    // ── proptest property tests ───────────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        /// normalize_host is idempotent: applying it twice yields the same
        /// result as applying it once.
        #[test]
        fn normalize_host_idempotent(host in "[a-z0-9.-]{1,63}") {
            let once = normalize_host(&host);
            let twice = normalize_host(&once);
            prop_assert_eq!(once, twice);
        }

        /// normalize_host lowercases: the output contains no uppercase ASCII.
        #[test]
        fn normalize_host_output_is_lowercase(host in "[A-Za-z0-9.:-]{1,63}") {
            let result = normalize_host(&host);
            prop_assert!(!result.chars().any(|c| c.is_ascii_uppercase()),
                "uppercase leaked into normalized host: {result:?} from {host:?}");
        }

        /// normalize_host never panics, even on hostile input.
        #[test]
        fn normalize_host_never_panics(input in "\\PC{0,128}") {
            let _ = normalize_host(&input);
        }

        /// parent_domain is idempotent: re-normalizing the output does not
        /// change it.
        #[test]
        fn parent_domain_idempotent(host in "[a-z0-9.-]{1,63}") {
            let once = parent_domain(&host);
            let twice = parent_domain(&once);
            prop_assert_eq!(once, twice);
        }

        /// parent_domain never panics, even on hostile input.
        #[test]
        fn parent_domain_never_panics(input in "\\PC{0,128}") {
            let _ = parent_domain(&input);
        }

        /// parent_domain of a bare IPv4 address returns the address unchanged.
        #[test]
        fn parent_domain_ipv4_unchanged(a in 0u8..=255, b in 0u8..=255, c in 0u8..=255, d in 0u8..=255) {
            let ip = format!("{a}.{b}.{c}.{d}");
            prop_assert_eq!(parent_domain(&ip), ip);
        }

        /// Sibling subdomains of the same registrable parent map to the
        /// same parent_domain output.
        #[test]
        fn siblings_share_parent(
            sub1 in "[a-z]{1,10}",
            sub2 in "[a-z]{1,10}",
            parent in "[a-z]{1,20}\\.[a-z]{2,6}"
        ) {
            // Only when the two sub-labels differ (otherwise it's the same host).
            prop_assume!(sub1 != sub2);
            let h1 = format!("{sub1}.{parent}");
            let h2 = format!("{sub2}.{parent}");
            prop_assert_eq!(parent_domain(&h1), parent_domain(&h2));
        }
    }
}
