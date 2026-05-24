//! Deep truth/precision tests for `gossan_origin::util::is_routable_ip`.
//!
//! This is THE precision gate for origin discovery  -  every scanner
//! (`dns_history`, `ssl_cert`, `dns_misconfig`) filters candidate IPs
//! through it. A gap here emits a non-routable junk IP as "the origin",
//! sending the whole engagement at a host that does not exist (or at an
//! internal address  -  an SSRF-flavoured false lead). Passive/DNS-history
//! sources routinely contain exactly this junk (CGNAT, TEST-NET
//! examples, IPv4-mapped v6), so the gaps are not theoretical.
//!
//! Contract-first: asserts the correct routability per IANA/RFC. The
//! engine (`util.rs`) is fixed to satisfy this  -  never the reverse.
//! Boundary cases guard against OVER-blocking (rejecting a legitimate
//! public IP next to a reserved range is a recall bug, just as bad).

use gossan_origin::util::is_routable_ip;

fn ip(s: &str) -> std::net::IpAddr {
    s.parse().expect("test ip literal")
}

/// Genuinely public IPs MUST stay routable (recall side).
#[test]
fn accepts_globally_routable() {
    for s in [
        "1.1.1.1",
        "8.8.8.8",
        "203.0.114.0",       // just past TEST-NET-3 (.113.x)
        "9.255.255.255",     // just below 10/8
        "11.0.0.0",          // just above 10/8
        "100.63.255.255",    // just BELOW CGNAT 100.64/10
        "100.128.0.0",       // just ABOVE CGNAT /10
        "223.255.255.255",   // just below Class-E 240/4
        "2606:4700:4700::1111",
        "2a00:1450:4001:80e::200e",
    ] {
        assert!(is_routable_ip(ip(s)), "{s} is public and MUST be routable");
    }
}

/// Regression lock: the ranges the original code already handled stay
/// rejected (private / loopback / link-local / multicast / broadcast).
#[test]
fn still_rejects_originally_covered_ranges() {
    for s in [
        "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1",
        "127.0.0.1", "0.0.0.0", "255.255.255.255", "169.254.0.1",
        "224.0.0.1", "239.255.255.255",
        "::1", "fe80::1", "ff02::1", "fc00::1", "fd12:3456::1", "::",
    ] {
        assert!(!is_routable_ip(ip(s)), "{s} must remain non-routable");
    }
}

/// THE gaps. Each of these was reported ROUTABLE by the std-predicate
/// implementation and is real junk in passive/DNS-history data.
#[test]
fn rejects_cgnat_testnet_and_other_reserved_v4() {
    let non_routable = [
        // RFC 6598 carrier-grade NAT  -  ubiquitous in real infra; NOT
        // covered by Ipv4Addr::is_private().
        ("100.64.0.1", "CGNAT 100.64/10 low"),
        ("100.96.0.1", "CGNAT 100.64/10 mid"),
        ("100.127.255.255", "CGNAT 100.64/10 high"),
        // RFC 5737 documentation ranges  -  literally appear in example
        // DNS records that leak into history sources.
        ("192.0.2.5", "TEST-NET-1"),
        ("198.51.100.7", "TEST-NET-2"),
        ("203.0.113.9", "TEST-NET-3"),
        // RFC 2544 benchmarking.
        ("198.18.0.1", "benchmark 198.18/15 low"),
        ("198.19.255.255", "benchmark 198.18/15 high"),
        // RFC 1122 "this network".
        ("0.1.2.3", "0.0.0.0/8 this-network"),
        // RFC 1112 reserved / Class-E.
        ("240.0.0.1", "Class-E 240/4 low"),
        ("250.1.2.3", "Class-E 240/4 mid"),
        // RFC 6890 IETF protocol assignments.
        ("192.0.0.1", "192.0.0.0/24 protocol"),
    ];
    for (s, why) in non_routable {
        assert!(
            !is_routable_ip(ip(s)),
            "{s} ({why}) must NOT be a routable origin candidate"
        );
    }
}

/// IPv4-mapped IPv6 must inherit the embedded IPv4's routability  -  a
/// `::ffff:10.0.0.1` is a private IPv4 wearing a v6 hat (a classic
/// filter-bypass) and was reported routable.
#[test]
fn ipv4_mapped_v6_inherits_v4_rules() {
    assert!(
        !is_routable_ip(ip("::ffff:10.0.0.1")),
        "IPv4-mapped private must be non-routable"
    );
    assert!(
        !is_routable_ip(ip("::ffff:127.0.0.1")),
        "IPv4-mapped loopback must be non-routable"
    );
    assert!(
        !is_routable_ip(ip("::ffff:100.64.0.1")),
        "IPv4-mapped CGNAT must be non-routable"
    );
    assert!(
        is_routable_ip(ip("::ffff:8.8.8.8")),
        "IPv4-mapped PUBLIC must stay routable (no over-block)"
    );
}

/// IPv6 documentation range (RFC 3849) is not a real origin.
#[test]
fn rejects_v6_documentation_range() {
    assert!(!is_routable_ip(ip("2001:db8::1")), "2001:db8::/32 is docs");
    assert!(
        !is_routable_ip(ip("2001:0db8:dead:beef::1")),
        "2001:db8::/32 is docs (any host)"
    );
    // A real global-unicast 2000::/3 address must still pass.
    assert!(is_routable_ip(ip("2001:4860:4860::8888")));
}
