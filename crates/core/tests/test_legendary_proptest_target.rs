use gossan_core::target::{
    Target, DomainTarget, HostTarget, ServiceTarget, DiscoverySource, Protocol
};
use proptest::prelude::*;
use std::net::{IpAddr, Ipv4Addr};

fn ip_strategy() -> impl Strategy<Value = std::net::IpAddr> {
    any::<(u8, u8, u8, u8)>().prop_map(|(a, b, c, d)| IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
}

proptest! {
    #[test]
    fn test_domain_target_invariant(domain in "[a-zA-Z0-9.-]{1,200}") {
        let t = Target::Domain(DomainTarget {
            domain: domain.clone(),
            source: DiscoverySource::Seed,
        });
        
        assert_eq!(t.domain(), Some(domain.as_str()));
        assert_eq!(t.ip(), None);
        // Note: target_domain implementation does not lowercase domains directly, it just returns string formatting for domains.
        assert_eq!(t.base_url(), Some(format!("https://{}/", domain)));
    }

    #[test]
    fn test_host_target_invariant(ip in ip_strategy(), domain in "[a-zA-Z0-9.-]{1,200}") {
        let t = Target::Host(HostTarget {
            ip,
            domain: Some(domain.clone()),
        });
        
        assert_eq!(t.domain(), Some(domain.as_str()));
        assert_eq!(t.ip(), Some(ip));
        assert_eq!(t.base_url(), Some(format!("http://{}/", ip)));
    }

    #[test]
    fn test_service_target_invariant(
        ip in ip_strategy(),
        // Restrict to lowercase + a single dot to avoid URL host
        // normalization (case-folding, punycode, trailing-dot strip)
        // that would make the substring assertion below brittle.
        host_label in "[a-z0-9]{1,30}",
        tld_label in "[a-z]{2,10}",
        port in 1u16..65535,
        tls in any::<bool>(),
    ) {
        let domain = format!("{host_label}.{tld_label}");
        let t = Target::Service(ServiceTarget {
            host: HostTarget {
                ip,
                domain: Some(domain.clone()),
            },
            port,
            protocol: Protocol::Tcp,
            banner: None,
            tls,
        });

        assert_eq!(t.domain(), Some(domain.as_str()));
        assert_eq!(t.ip(), Some(ip));

        if let Some(base) = t.base_url() {
            if tls || port == 443 || port == 8443 {
                assert!(base.starts_with("https://"));
            } else {
                assert!(base.starts_with("http://"));
            }
            // The host must be the supplied domain (URL preserves
            // lowercase ASCII labels verbatim, no normalization
            // applies in this charset).
            assert!(
                base.contains(&domain) || base.contains(&ip.to_string()),
                "base_url {base} missing both {domain} and {ip}"
            );
        }
    }
}
