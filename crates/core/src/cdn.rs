//! CDN/WAF anycast IP-range classification.
//!
//! Embeds well-known CDN provider CIDR ranges at compile time and
//! exposes [`is_cdn_ip`] for callers that need to suppress false
//! positives caused by CDN edge IPs (notably the origin validator,
//! where a host-header swap to a CDN edge returns the same content
//! as the CDN-routed baseline).
//!
//! The range list is in [`cdn_ranges.txt`] alongside this source file.
//! Update it periodically from each provider's official IP list.

use std::net::IpAddr;
use std::sync::OnceLock;

use ipnet::IpNet;

/// Embedded CDN CIDR ranges.
const CDN_RANGES_TEXT: &str = include_str!("cdn_ranges.txt");

static CDN_RANGES: OnceLock<Vec<IpNet>> = OnceLock::new();

/// Parse the embedded range file into CIDRs, ignoring comments and blanks.
fn parse_ranges(text: &str) -> Vec<IpNet> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.parse::<IpNet>().ok())
        .collect()
}

/// Return the built-in CDN CIDR ranges, initializing the cache on first call.
pub fn cdn_ranges() -> &'static [IpNet] {
    CDN_RANGES.get_or_init(|| parse_ranges(CDN_RANGES_TEXT))
}

/// True when `ip` falls inside any built-in CDN/WAF anycast range.
///
/// Callers that load a custom range file at runtime (e.g.
/// `gossan_portscan::cdn::load_ranges`) should use their own list;
/// this function is the zero-config floor for crates that do not
/// configure one.
#[must_use]
pub fn is_cdn_ip(ip: IpAddr) -> bool {
    cdn_ranges().iter().any(|net| net.contains(&ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_load_and_are_nonempty() {
        let r = cdn_ranges();
        assert!(!r.is_empty(), "built-in CDN range list must not be empty");
    }

    #[test]
    fn cloudflare_ipv4_detected() {
        assert!(is_cdn_ip("104.16.0.1".parse().unwrap()));
        assert!(is_cdn_ip("172.64.0.1".parse().unwrap()));
    }

    #[test]
    fn cloudflare_ipv6_detected() {
        assert!(is_cdn_ip("2606:4700::1".parse().unwrap()));
    }

    #[test]
    fn cloudfront_detected() {
        assert!(is_cdn_ip("13.32.0.1".parse().unwrap()));
        assert!(is_cdn_ip("99.84.0.1".parse().unwrap()));
    }

    #[test]
    fn fastly_detected() {
        assert!(is_cdn_ip("151.101.0.1".parse().unwrap()));
        assert!(is_cdn_ip("199.232.0.1".parse().unwrap()));
    }

    #[test]
    fn akamai_detected() {
        assert!(is_cdn_ip("23.32.0.1".parse().unwrap()));
        assert!(is_cdn_ip("72.246.0.1".parse().unwrap()));
    }

    #[test]
    fn non_cdn_ip_not_detected() {
        assert!(!is_cdn_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_cdn_ip("1.2.3.4".parse().unwrap()));
        assert!(!is_cdn_ip("203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn all_ranges_parse_successfully() {
        let r = cdn_ranges();
        // Every entry in the text file must parse; parse_ranges drops
        // failures silently, so assert the count matches the non-comment
        // line count.
        let expected = CDN_RANGES_TEXT
            .lines()
            .map(|l| l.split('#').next().unwrap_or("").trim())
            .filter(|l| !l.is_empty())
            .count();
        assert_eq!(
            r.len(),
            expected,
            "some CDN range lines failed to parse"
        );
    }

    #[test]
    fn is_cdn_ip_never_panics_on_any_ip() {
        // Boundary: all-zero and all-one addresses must not panic.
        assert!(!is_cdn_ip("0.0.0.0".parse().unwrap()));
        assert!(!is_cdn_ip("255.255.255.255".parse().unwrap()));
        assert!(!is_cdn_ip("::".parse().unwrap()));
        assert!(!is_cdn_ip("::1".parse().unwrap()));
        // A real CDN edge IP still works.
        assert!(is_cdn_ip("104.16.0.1".parse().unwrap()));
    }
}
