//! Serde roundtrip tests for every Target variant.
//!
//! Each variant must serialize → JSON → deserialize back into a value that
//! preserves the discriminating fields (domain/ip/url/cidr/etc.). Adding a
//! new Target variant without an entry here is a regression.

use gossan_core::target::{
    DiscoveredForm, DiscoveredParam, DiscoverySource, DomainTarget, HostTarget,
    InternalPackageTarget, NetworkTarget, ParamLocation, ParamSource, Protocol, RepositoryTarget,
    ScmService, ServiceTarget, Target, TechCategory, Technology, WebAssetTarget,
};
use url::Url;

fn rt(target: &Target) -> Target {
    let json = serde_json::to_string(target).expect("serialize");
    serde_json::from_str(&json).expect("deserialize")
}

#[test]
fn roundtrip_domain() {
    let t = Target::Domain(DomainTarget {
        domain: "api.example.com".into(),
        source: DiscoverySource::CertificateTransparency,
    });
    let r = rt(&t);
    assert_eq!(r.domain(), Some("api.example.com"));
    let Target::Domain(d) = r else {
        panic!("variant changed");
    };
    assert_eq!(d.source, DiscoverySource::CertificateTransparency);
}

#[test]
fn roundtrip_host_v4_with_domain() {
    let t = Target::Host(HostTarget {
        ip: "203.0.113.5".parse().unwrap(),
        domain: Some("a.example.com".into()),
    });
    let r = rt(&t);
    assert_eq!(r.ip(), Some("203.0.113.5".parse().unwrap()));
    assert_eq!(r.domain(), Some("a.example.com"));
}

#[test]
fn roundtrip_host_v6_no_domain() {
    let t = Target::Host(HostTarget {
        ip: "2001:db8::1".parse().unwrap(),
        domain: None,
    });
    let r = rt(&t);
    assert_eq!(r.ip(), Some("2001:db8::1".parse().unwrap()));
    assert_eq!(r.domain(), None);
}

#[test]
fn roundtrip_service_with_banner_and_tls() {
    let svc = ServiceTarget {
        host: HostTarget {
            ip: "10.0.0.1".parse().unwrap(),
            domain: Some("svc.example.com".into()),
        },
        port: 8443,
        protocol: Protocol::Tcp,
        banner: Some("HTTP/1.1 200 OK".into()),
        tls: true,
    };
    let t = Target::Service(svc.clone());
    let r = rt(&t);
    let Target::Service(s) = r else {
        panic!("variant changed");
    };
    assert_eq!(s.port, svc.port);
    assert_eq!(s.protocol, svc.protocol);
    assert_eq!(s.tls, svc.tls);
    assert_eq!(s.banner.as_deref(), Some("HTTP/1.1 200 OK"));
    assert_eq!(s.host.ip, svc.host.ip);
}

#[test]
fn roundtrip_web_with_full_payload() {
    let svc = ServiceTarget {
        host: HostTarget {
            ip: "192.0.2.10".parse().unwrap(),
            domain: Some("www.example.com".into()),
        },
        port: 443,
        protocol: Protocol::Tcp,
        banner: None,
        tls: true,
    };
    let web = WebAssetTarget {
        url: Url::parse("https://www.example.com/login").unwrap(),
        service: svc,
        tech: vec![Technology {
            name: "nginx".into(),
            version: Some("1.27.1".into()),
            category: TechCategory::Server,
            confidence: 95,
        }],
        status: 200,
        title: Some("Login | Example".into()),
        favicon_hash: Some(-1234567890),
        body_hash: Some("abc123def4567890".into()),
        forms: vec![DiscoveredForm {
            action: "/login".into(),
            method: "POST".into(),
            inputs: vec![
                ("user".into(), "text".into()),
                ("pass".into(), "password".into()),
            ],
        }],
        params: vec![DiscoveredParam {
            name: "next".into(),
            location: ParamLocation::Query,
            source: ParamSource::UrlObserved,
        }],
    };
    let t = Target::Web(Box::new(web));
    let r = rt(&t);
    let Target::Web(w) = r else {
        panic!("variant changed");
    };
    assert_eq!(w.url.as_str(), "https://www.example.com/login");
    assert_eq!(w.status, 200);
    assert_eq!(w.title.as_deref(), Some("Login | Example"));
    assert_eq!(w.favicon_hash, Some(-1234567890));
    assert_eq!(w.body_hash.as_deref(), Some("abc123def4567890"));
    assert_eq!(w.tech.len(), 1);
    assert_eq!(w.tech[0].name, "nginx");
    assert_eq!(w.tech[0].confidence, 95);
    assert_eq!(w.forms.len(), 1);
    assert_eq!(w.forms[0].inputs.len(), 2);
    assert_eq!(w.params.len(), 1);
    assert_eq!(w.params[0].name, "next");
}

#[test]
fn roundtrip_network() {
    let t = Target::Network(NetworkTarget {
        cidr: "198.51.100.0/24".into(),
        source: DiscoverySource::Asn,
    });
    let r = rt(&t);
    let Target::Network(n) = r else {
        panic!("variant changed");
    };
    assert_eq!(n.cidr, "198.51.100.0/24");
    assert_eq!(n.source, DiscoverySource::Asn);
}

#[test]
fn roundtrip_repository() {
    let t = Target::Repository(RepositoryTarget {
        url: Url::parse("https://github.com/santhsecurity/gossan").unwrap(),
        service: ScmService::GitHub,
        source: DiscoverySource::GitHub,
        branch: Some("main".into()),
    });
    let r = rt(&t);
    let Target::Repository(repo) = r else {
        panic!("variant changed");
    };
    assert_eq!(
        repo.url.as_str(),
        "https://github.com/santhsecurity/gossan"
    );
    assert_eq!(repo.service, ScmService::GitHub);
    assert_eq!(repo.branch.as_deref(), Some("main"));
}

#[test]
fn roundtrip_internal_package() {
    let t = Target::InternalPackage(InternalPackageTarget {
        name: "@myorg/private-utils".into(),
        source_repo: Url::parse("https://github.com/myorg/app").unwrap(),
        ecosystem: "npm".into(),
    });
    let r = rt(&t);
    let Target::InternalPackage(p) = r else {
        panic!("variant changed");
    };
    assert_eq!(p.name, "@myorg/private-utils");
    assert_eq!(p.source_repo.as_str(), "https://github.com/myorg/app");
    assert_eq!(p.ecosystem, "npm");
}

#[test]
fn json_kind_tags_match_variant_names() {
    let cases = [
        (
            Target::Domain(DomainTarget {
                domain: "x".into(),
                source: DiscoverySource::Seed,
            }),
            "domain",
        ),
        (
            Target::Host(HostTarget {
                ip: "1.1.1.1".parse().unwrap(),
                domain: None,
            }),
            "host",
        ),
        (
            Target::Network(NetworkTarget {
                cidr: "1.0.0.0/8".into(),
                source: DiscoverySource::Asn,
            }),
            "network",
        ),
        (
            Target::InternalPackage(InternalPackageTarget {
                name: "x".into(),
                source_repo: Url::parse("https://example.com").unwrap(),
                ecosystem: "npm".into(),
            }),
            "internal_package",
        ),
    ];
    for (t, expected_tag) in cases {
        let v: serde_json::Value = serde_json::to_value(&t).unwrap();
        assert_eq!(v.get("kind").and_then(|s| s.as_str()), Some(expected_tag));
    }
}
