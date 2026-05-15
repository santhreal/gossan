use gossan_core::target::{
    Target, DomainTarget, HostTarget, ServiceTarget, WebAssetTarget, DiscoverySource, Protocol
};
use url::Url;

#[test]
fn test_target_adversarial_huge_domain() {
    let domain = "a".repeat(1_000_000);
    let target = Target::Domain(DomainTarget {
        domain: domain.clone(),
        source: DiscoverySource::Seed,
    });
    
    // Memory constraints test. It shouldn't panic when we fetch it.
    assert_eq!(target.domain().unwrap(), domain.as_str());
}

#[test]
fn test_target_adversarial_null_bytes_in_domain() {
    let domain = "null\0byte.com".to_string();
    let target = Target::Domain(DomainTarget {
        domain: domain.clone(),
        source: DiscoverySource::Seed,
    });
    
    // String slices don't care about null bytes in Rust, but good to test
    assert_eq!(target.domain().unwrap(), domain.as_str());
    assert!(target.base_url().unwrap().contains("null\0byte.com"));
}

#[test]
fn test_target_adversarial_zero_port_service() {
    let target = Target::Service(ServiceTarget {
        host: HostTarget {
            ip: "127.0.0.1".parse().unwrap(),
            domain: None,
        },
        port: 0,
        protocol: Protocol::Tcp,
        banner: None,
        tls: false,
    });

    // We shouldn't panic when asking for base_url of a port 0 service
    let base_url = target.base_url();
    assert!(base_url.is_some());
}

#[test]
fn test_target_adversarial_base_url_long_url() {
    // Rust Url parsing does not easily panic on long urls, it allocates or errors.
    // If we parse a massive URL and ask for base_url, it should strip path, query, etc
    // without panic.
    let path = "a".repeat(100_000);
    let url_str = format!("https://example.com/{}?foo=bar#baz", path);
    let target = Target::Web(Box::new(WebAssetTarget {
        url: Url::parse(&url_str).unwrap(),
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
    }));

    let base = target.base_url().unwrap();
    // Path should be stripped in target.rs web base_url implementation
    assert_eq!(base, "https://example.com/");
}
