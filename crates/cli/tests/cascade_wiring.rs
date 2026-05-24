//! Cascade WIRING contract  -  the type-level proof that the gossan
//! pipeline is fully connected.
//!
//! `gossan scan` is a topological DAG: a phase only ever sees targets
//! produced by an EARLIER phase, and a scanner only runs on a target
//! its `accepts()` returns true for. The cascade that carries a bare
//! seed (and every discovered subdomain) to the web-app layer is:
//!
//!   Domain ──SubdomainScanner(T0)──▶ Domain (subdomains)
//!   Domain ──PortScanner(T1)──────▶ Service (open web ports)
//!   Service ─TechStackScanner(T2)─▶ Web
//!   Web ────Js/Hidden/Crawl(T3)──▶ findings
//!
//! Every arrow is a `produces type X` / `consumes type X` handshake.
//! If ANY scanner's `accepts()` drifts so a link no longer type-checks
//! at runtime, the web-app layer silently receives nothing and the
//! whole scan "finds nothing"  -  the literal bug-bounty report. These
//! tests fail the instant that handshake breaks, with no network and
//! no flakiness. They are the static companion to the live
//! `scan_full_cascade_*` e2e in `vuln_app_e2e.rs`.

use gossan_core::{
    DiscoverySource, DomainTarget, HostTarget, Protocol, Scanner, ServiceTarget, Target,
};
use std::net::{IpAddr, Ipv4Addr};

fn domain(d: &str) -> Target {
    Target::Domain(DomainTarget {
        domain: d.to_string(),
        source: DiscoverySource::Seed,
    })
}

/// A web `Service` exactly as the pipeline synthesises / portscan
/// emits one (HTTP/1.1 banner, 443/tls)  -  the input techstack must
/// accept to produce the `Web` the app layer consumes.
fn web_service(host: &str, port: u16, tls: bool) -> Target {
    Target::Service(ServiceTarget {
        host: HostTarget {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            domain: Some(host.to_string()),
        },
        port,
        protocol: Protocol::Tcp,
        banner: Some("HTTP/1.1 200 OK".to_string()),
        tls,
    })
}

fn web(url: &str) -> Target {
    gossan_core::testkit::web_target(url)
}

fn subdomain() -> impl Scanner {
    gossan_subdomain::SubdomainScanner
}
fn portscan() -> impl Scanner {
    gossan_portscan::PortScanner
}
fn techstack() -> impl Scanner {
    gossan_techstack::TechStackScanner
}

/// LINK 0→1: the seed (a `Domain`) and every subdomain the subdomain
/// scanner emits (also a `Domain`) MUST be accepted by both the
/// subdomain scanner (to recurse) and the port scanner (so each
/// discovered host actually gets scanned, not stranded).
#[test]
fn seed_and_discovered_domains_feed_subdomain_and_portscan() {
    let seed = domain("example.com");
    let discovered = domain("api.example.com");

    assert!(
        subdomain().accepts(&seed),
        "subdomain scanner must accept the seed Domain (phase 0 starves otherwise)"
    );
    assert!(
        subdomain().accepts(&discovered),
        "subdomain scanner must accept a discovered Domain (recursive enumeration)"
    );
    assert!(
        portscan().accepts(&seed),
        "portscan must accept the seed Domain  -  it is the ONLY producer of \
         the Service the web layer ultimately needs"
    );
    assert!(
        portscan().accepts(&discovered),
        "portscan must accept a DISCOVERED subdomain Domain  -  else every \
         subdomain found is invisible to the entire web-app layer \
         (found subdomains, found nothing on them)"
    );
}

/// LINK 1→2: portscan emits a `Service`; a web Service must be
/// recognised as web AND accepted by techstack (the Service→Web
/// hinge). If techstack stops accepting web Services, js/hidden/crawl
/// never get a single `Web` target.
#[test]
fn web_service_is_web_and_feeds_techstack() {
    for (port, tls) in [(443u16, true), (80, false), (8443, true), (3000, false)] {
        let svc = web_service("example.com", port, tls);
        if let Target::Service(s) = &svc {
            assert!(
                s.is_web(),
                "an HTTP/1.1-bannered service on :{port} must be is_web() \
                 (techstack's accept gate keys on it)"
            );
        }
        assert!(
            techstack().accepts(&svc),
            "techstack must accept a web Service on :{port}  -  it is the \
             SOLE Service→Web converter feeding the app layer"
        );
    }
}

/// LINK 2→3: techstack emits a `Web`; EVERY web-app scanner must
/// accept it. A drift here (e.g. js narrowing `accepts` to a subtype)
/// silently removes that scanner's entire output from `gossan scan`.
#[test]
fn web_target_feeds_every_app_layer_scanner() {
    let w = web("http://example.com:8080/");
    let app: Vec<(&str, Box<dyn Scanner>)> = vec![
        ("js", Box::new(gossan_js::JsScanner)),
        ("hidden", Box::new(gossan_hidden::HiddenScanner)),
        ("crawl", Box::new(gossan_crawl::CrawlScanner)),
        ("headless", Box::new(gossan_headless::HeadlessScanner)),
        ("cloud", Box::new(gossan_cloud::CloudScanner)),
    ];
    for (name, s) in &app {
        assert!(
            s.accepts(&w),
            "{name} must accept a Web target  -  it is the cascade's only \
             input to the web-app layer; rejecting it = that scanner \
             produces nothing on a full scan"
        );
    }
}

/// NEGATIVE / why the cascade is mandatory: the web-app scanners do
/// NOT accept a bare `Domain`. This is correct  -  and it is precisely
/// why the Domain→Service→Web cascade must stay wired: a discovered
/// subdomain `Domain` is invisible to js/hidden until portscan+
/// techstack convert it. This test documents and pins that contract
/// so nobody "fixes" the cascade by deleting portscan/techstack.
#[test]
fn app_layer_does_not_short_circuit_the_cascade() {
    let d = domain("api.example.com");
    assert!(
        !gossan_js::JsScanner.accepts(&d),
        "js must NOT accept a bare Domain  -  proves the Service/Web \
         cascade (portscan→techstack) is REQUIRED, not optional"
    );
    assert!(
        !gossan_hidden::HiddenScanner.accepts(&d),
        "hidden must NOT accept a bare Domain  -  same cascade dependency"
    );
    // techstack must NOT accept a bare Domain either (it needs the
    // Service portscan produces)  -  the wiring is Domain→Service→Web,
    // strictly staged.
    assert!(
        !techstack().accepts(&d),
        "techstack consumes Service, not Domain  -  portscan must run first"
    );
}

/// Every registered scanner reports a STABLE, NON-EMPTY name. The
/// pipeline keys module enable/disable and the phase-tier assignment
/// (`registry::register` matches on `name()`) on this string  -  a blank
/// or colliding name silently mis-tiers or disables a whole stage.
/// (The live registry build itself is exercised end-to-end by the
/// `scan_full_cascade_*` tests, which drive the real binary.)
#[test]
fn every_scanner_has_a_stable_nonempty_name() {
    let scanners: Vec<Box<dyn Scanner>> = vec![
        Box::new(gossan_subdomain::SubdomainScanner),
        Box::new(gossan_portscan::PortScanner),
        Box::new(gossan_techstack::TechStackScanner),
        Box::new(gossan_js::JsScanner),
        Box::new(gossan_hidden::HiddenScanner),
        Box::new(gossan_crawl::CrawlScanner),
        Box::new(gossan_headless::HeadlessScanner),
        Box::new(gossan_cloud::CloudScanner),
        Box::new(gossan_dns::DnsScanner),
        Box::new(gossan_horizontal::HorizontalScanner),
        Box::new(gossan_scm::ScmScanner),
    ];
    let mut names: Vec<&str> = Vec::new();
    for s in &scanners {
        let n = s.name();
        assert!(!n.trim().is_empty(), "a scanner reported an empty name()");
        // The phase-tier match in registry::register is exact on these.
        names.push(n);
    }
    let mut uniq = names.clone();
    uniq.sort_unstable();
    uniq.dedup();
    assert_eq!(
        uniq.len(),
        names.len(),
        "duplicate scanner name()  -  module gating mis-fires: {names:?}"
    );
    // The phase-tier producer→consumer order the cascade depends on
    // (registry::register hard-codes these exact strings).
    for must in [
        "subdomain", "portscan", "techstack", "js", "hidden", "crawl",
    ] {
        assert!(
            names.contains(&must),
            "scanner name `{must}` changed  -  registry::register's tier \
             match keys on it; a rename silently mis-tiers the stage and \
             severs the cascade: {names:?}"
        );
    }
}
