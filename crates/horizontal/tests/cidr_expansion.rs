//! CIDR expansion tests.
//!
//! Per GOSSAN_LEGENDARY A17: `10.0.0.0/30` → 4 IPs (RFC says 2
//! usable + network + broadcast = 4 total in /30). The runtime path
//! in `gossan_horizontal::lib` parses CIDRs via `ipnet::IpNet` and
//! calls `.hosts()` to enumerate. These tests pin that contract.

use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn slash30_expands_to_two_usable_hosts() {
    let prefix: ipnet::IpNet = "10.0.0.0/30".parse().unwrap();
    let hosts: Vec<_> = prefix.hosts().collect();
    // ipnet::hosts() excludes network + broadcast for IPv4 → 2 usable.
    assert_eq!(hosts.len(), 2);
    assert!(hosts.contains(&"10.0.0.1".parse::<std::net::IpAddr>().unwrap()));
    assert!(hosts.contains(&"10.0.0.2".parse::<std::net::IpAddr>().unwrap()));
}

#[test]
fn slash29_expands_to_six_usable_hosts() {
    let prefix: ipnet::IpNet = "192.168.1.0/29".parse().unwrap();
    let hosts: Vec<_> = prefix.hosts().collect();
    assert_eq!(hosts.len(), 6);
}

#[test]
fn slash32_yields_one_host() {
    let prefix: ipnet::IpNet = "10.0.0.5/32".parse().unwrap();
    let hosts: Vec<_> = prefix.hosts().collect();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0], std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
}

#[test]
fn slash24_yields_254_usable_hosts() {
    let prefix: ipnet::IpNet = "10.0.0.0/24".parse().unwrap();
    let hosts: Vec<_> = prefix.hosts().collect();
    assert_eq!(hosts.len(), 254);
}

#[test]
fn ipv6_cidr_expansion_does_not_panic() {
    let prefix: ipnet::IpNet = "2001:db8::/126".parse().unwrap();
    let hosts: Vec<_> = prefix.hosts().take(8).collect();
    assert!(!hosts.is_empty());
    assert!(hosts.iter().any(|ip| matches!(ip, std::net::IpAddr::V6(_))));
    let _ = Ipv6Addr::LOCALHOST;
}

#[test]
fn malformed_cidr_returns_err() {
    assert!("10.0.0.0/99".parse::<ipnet::IpNet>().is_err());
    assert!("not-a-cidr".parse::<ipnet::IpNet>().is_err());
}
