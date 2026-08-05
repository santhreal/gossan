//! Shared utilities for origin discovery. IP filtering, bounded I/O, etc.

use std::net::IpAddr;

/// Returns `true` only for globally routable IPs that could plausibly be a
/// reachable origin host.
///
/// Defers to the canonical [`bogon::ip_addr_is_bogon`] classifier for every
/// private / reserved / metadata range it owns (RFC 1918, loopback,
/// link-local, broadcast, CGNAT, TEST-NET-1/2/3, benchmark, IETF protocol
/// assignment, and the IPv6 ULA / link-local / Teredo / ORCHIDv2 / discard /
/// NAT64 / 6to4-bogon ranges), then layers origin-discovery's stricter
/// reachability checks for the few addresses bogon intentionally *permits*
/// (multicast, Class-E `240.0.0.0/4`, the rest of `0.0.0.0/8`) but which are
/// never a real web origin. Per bogon's own guidance, stricter consumers
/// layer on top of the predicate rather than forking it.
pub fn is_routable_ip(ip: IpAddr) -> bool {
    // Everything SSRF policy refuses can never be a routable origin.
    if bogon::ip_addr_is_bogon(ip) {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            let u = u32::from_be_bytes(v4.octets());
            // bogon permits these; origin discovery does not.
            !(v4.is_multicast()
                // 0.0.0.0/8 "this network" (bogon refuses only 0.0.0.0).
                || (u & 0xff000000) == 0x00000000
                // Class-E 240.0.0.0/4 (incl. 255.255.255.255 broadcast).
                || (u & 0xf0000000) == 0xf0000000)
        }
        // bogon already refuses every non-routable IPv6 range this scanner
        // enumerated (plus Teredo / NAT64 / ORCHIDv2, which are likewise
        // never origins), so clearing the bogon check is sufficient.
        IpAddr::V6(_) => true,
    }
}

/// Bounded response readers — single owner is [`gossan_core::net`].
pub use gossan_core::net::{bounded_bytes, bounded_json, bounded_text};

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn routable_ip_accepts_public() {
        assert!(is_routable_ip("1.1.1.1".parse().unwrap()));
        assert!(is_routable_ip("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn routable_ip_rejects_private() {
        assert!(!is_routable_ip("10.0.0.1".parse().unwrap()));
        assert!(!is_routable_ip("192.168.1.1".parse().unwrap()));
        assert!(!is_routable_ip("172.16.0.1".parse().unwrap()));
    }

    #[test]
    fn routable_ip_rejects_loopback() {
        assert!(!is_routable_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_routable_ip("::1".parse().unwrap()));
    }

    #[test]
    fn routable_ip_rejects_link_local() {
        assert!(!is_routable_ip("169.254.0.1".parse().unwrap()));
        assert!(!is_routable_ip("fe80::1".parse().unwrap()));
    }

    #[test]
    fn routable_ip_rejects_class_e_and_this_network() {
        // bogon intentionally permits these (it answers SSRF policy, not
        // routability); the origin-reachability layer must still reject
        // them so they never surface as an origin candidate.
        assert!(!is_routable_ip("240.0.0.1".parse().unwrap())); // Class-E 240/4
        assert!(!is_routable_ip("250.1.2.3".parse().unwrap())); // Class-E 240/4
        assert!(!is_routable_ip("0.1.2.3".parse().unwrap())); // 0.0.0.0/8
    }

    #[test]
    fn routable_ip_accepts_public_ipv6() {
        // A public IPv6 origin clears bogon and is routable.
        assert!(is_routable_ip("2606:4700::1111".parse().unwrap()));
    }

    #[test]
    fn routable_ip_rejects_multicast() {
        assert!(!is_routable_ip("224.0.0.1".parse().unwrap()));
        assert!(!is_routable_ip("ff02::1".parse().unwrap()));
    }

    proptest! {
        #[test]
        fn is_routable_ip_never_panics(ip in any::<[u8; 16]>()) {
            // Construct arbitrary IPv4 and IPv6 addresses from 16 bytes.
            let v4 = IpAddr::V4(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]));
            let v6 = IpAddr::V6(std::net::Ipv6Addr::from(ip));
            let _ = is_routable_ip(v4);
            let _ = is_routable_ip(v6);
        }
    }
}
