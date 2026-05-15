use gossan_core::target::{
    DiscoverySource, DomainTarget, HostTarget, NetworkTarget, Protocol, ServiceTarget, Target,
    WebAssetTarget,
};
use std::net::IpAddr;
use url::Url;

fn create_domain_target() -> Target {
    Target::Domain(DomainTarget {
        domain: "example.com".to_string(),
        source: DiscoverySource::Seed,
    })
}

fn create_host_target() -> Target {
    Target::Host(HostTarget {
        ip: "1.1.1.1".parse().unwrap(),
        domain: Some("example.com".to_string()),
    })
}

fn create_service_target() -> Target {
    Target::Service(ServiceTarget {
        host: HostTarget {
            ip: "1.1.1.1".parse().unwrap(),
            domain: Some("example.com".to_string()),
        },
        port: 443,
        protocol: Protocol::Tcp,
        banner: None,
        tls: true,
    })
}

fn create_web_target() -> Target {
    Target::Web(Box::new(WebAssetTarget {
        url: Url::parse("https://example.com").unwrap(),
        service: ServiceTarget {
            host: HostTarget {
                ip: "1.1.1.1".parse().unwrap(),
                domain: Some("example.com".to_string()),
            },
            port: 443,
            protocol: Protocol::Tcp,
            banner: None,
            tls: true,
        },
        tech: vec![],
        status: 200,
        title: None,
        favicon_hash: None,
        body_hash: None,
        forms: vec![],
        params: vec![],
    }))
}

fn create_network_target() -> Target {
    Target::Network(NetworkTarget {
        cidr: "1.1.1.0/24".to_string(),
        source: DiscoverySource::Seed,
    })
}

#[test]
fn test_target_domain_extraction() {
    assert_eq!(create_domain_target().domain(), Some("example.com"));
    assert_eq!(create_host_target().domain(), Some("example.com"));
    assert_eq!(create_service_target().domain(), Some("example.com"));
    assert_eq!(create_web_target().domain(), Some("example.com"));
    assert_eq!(create_network_target().domain(), None);
}

#[test]
fn test_target_ip_extraction() {
    let expected_ip: IpAddr = "1.1.1.1".parse().unwrap();
    assert_eq!(create_domain_target().ip(), None);
    assert_eq!(create_host_target().ip(), Some(expected_ip));
    assert_eq!(create_service_target().ip(), Some(expected_ip));
    assert_eq!(create_web_target().ip(), Some(expected_ip));
    assert_eq!(create_network_target().ip(), None);
}

#[test]
fn test_target_base_url_extraction() {
    assert_eq!(
        create_domain_target().base_url().unwrap(),
        "https://example.com/"
    );
    assert_eq!(create_host_target().base_url().unwrap(), "http://1.1.1.1/");
    assert_eq!(
        create_service_target().base_url().unwrap(),
        "https://example.com/"
    );
    assert_eq!(
        create_web_target().base_url().unwrap(),
        "https://example.com/"
    );
    assert_eq!(create_network_target().base_url(), None);
}
