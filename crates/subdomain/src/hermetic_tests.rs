//! Hermetic DNS discovery tests  -  exact name assertions against loopback zones.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use gossan_core::{net::resolver_port, Target};

use crate::bruteforce::run_bruteforce_with_words;
use crate::hermetic_dns::{
    gossan_resolver_for, resolver_for, test_env_lock, AdversarialMode, HermeticZone, HostRecords,
    WildcardMode,
};
use crate::wildcard::detect_wildcards;

fn host(
    a: Option<Ipv4Addr>,
    aaaa: Option<Ipv6Addr>,
    cname: Option<&str>,
) -> HostRecords {
    HostRecords {
        a,
        aaaa,
        cname: cname.map(str::to_string),
    }
}

async fn sleep_server() {
    tokio::time::sleep(Duration::from_millis(50)).await;
}

fn exact_set(found: &[String]) -> HashSet<&str> {
    found.iter().map(String::as_str).collect()
}

fn assert_exact(found: &[String], expected: &[&str]) {
    let got = exact_set(found);
    let want: HashSet<&str> = expected.iter().copied().collect();
    assert_eq!(
        got, want,
        "exact discovery set mismatch: got {found:?}, expected {expected:?}"
    );
}

/// PROVING: multi-hop CNAME chain (CNAME → CNAME → A) is still discovered.
#[tokio::test]
async fn multi_hop_cname_chain_is_discovered() {
    let mut hosts = HashMap::new();
    hosts.insert(
        "chain.example.com".to_string(),
        host(None, None, Some("hop.example.com")),
    );
    hosts.insert(
        "hop.example.com".to_string(),
        host(None, None, Some("leaf.example.com")),
    );
    hosts.insert(
        "leaf.example.com".to_string(),
        host(Some(Ipv4Addr::new(10, 0, 0, 1)), None, None),
    );
    let addr = HermeticZone {
        hosts,
        wildcard: WildcardMode::NxDomain,
        adversarial: AdversarialMode::Normal,
    }
    .serve()
    .await;
    sleep_server().await;

    let found = run_bruteforce_with_words(
        "example.com",
        &["chain"],
        resolver_for(addr),
        None,
        1,
    )
    .await
    .unwrap();
    assert_exact(&found, &["chain.example.com"]);
}

/// PROVING: explicit CNAME to a wildcard A target is a true positive (not filtered).
#[tokio::test]
async fn cname_to_wildcard_a_is_still_discovered() {
    let wild_ip = Ipv4Addr::new(1, 2, 3, 4);
    let mut hosts = HashMap::new();
    hosts.insert(
        "alias.example.com".to_string(),
        host(None, None, Some("sink.example.com")),
    );
    hosts.insert("sink.example.com".to_string(), host(Some(wild_ip), None, None));
    let addr = HermeticZone {
        hosts,
        wildcard: WildcardMode::NxDomain,
        adversarial: AdversarialMode::Normal,
    }
    .serve()
    .await;
    sleep_server().await;

    let wildcards = HashSet::from([IpAddr::V4(wild_ip)]);
    let found = run_bruteforce_with_words(
        "example.com",
        &["alias", "noise"],
        resolver_for(addr),
        Some(wildcards),
        1,
    )
    .await
    .unwrap();
    assert_exact(&found, &["alias.example.com"]);
}

/// PROVING: AAAA-only host is discovered (no A record).
#[tokio::test]
async fn aaaa_only_host_is_discovered() {
    let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let mut hosts = HashMap::new();
    hosts.insert(
        "v6only.example.com".to_string(),
        host(None, Some(v6), None),
    );
    let addr = HermeticZone {
        hosts,
        wildcard: WildcardMode::NxDomain,
        adversarial: AdversarialMode::Normal,
    }
    .serve()
    .await;
    sleep_server().await;

    let found = run_bruteforce_with_words(
        "example.com",
        &["v6only"],
        resolver_for(addr),
        None,
        1,
    )
    .await
    .unwrap();
    assert_exact(&found, &["v6only.example.com"]);
}

/// PROVING + ADVERSARIAL: wildcard labels are suppressed; explicit records survive.
#[tokio::test]
async fn wildcard_filter_keeps_real_and_drops_garbage() {
    let wild_ip = Ipv4Addr::new(1, 2, 3, 4);
    let real_ip = Ipv4Addr::new(9, 9, 9, 9);
    let mut hosts = HashMap::new();
    hosts.insert("api.example.com".to_string(), host(Some(real_ip), None, None));
    hosts.insert(
        "real.example.com".to_string(),
        host(Some(real_ip), None, None),
    );
    let addr = HermeticZone {
        hosts,
        wildcard: WildcardMode::A(wild_ip),
        adversarial: AdversarialMode::Normal,
    }
    .serve()
    .await;
    sleep_server().await;

    let resolver = resolver_for(addr);
    let wildcards = detect_wildcards("example.com", &resolver, 3).await;
    assert!(
        wildcards.contains(&IpAddr::V4(wild_ip)),
        "wildcard probe must learn wildcard IP"
    );

    let found = run_bruteforce_with_words(
        "example.com",
        &["api", "real", "zzzgossan-garbage-label"],
        resolver,
        Some(wildcards),
        1,
    )
    .await
    .unwrap();
    assert_exact(&found, &["api.example.com", "real.example.com"]);
}

/// PRECISION LINCHPIN: on a NON-wildcard zone `detect_wildcards` MUST
/// return an empty set. The existing suite only ever asserts the set is
/// *non-empty* on a wildcard zone  -  the asymmetric (and more dangerous)
/// side was untested: if detection ever reports a phantom wildcard IP
/// here, bruteforce compares every hit against that bogus set and
/// silently DROPS real subdomains that happen to share the IP  -  total
/// recall destruction with no error. End-to-end: an empty wildcard set
/// must therefore filter nothing.
#[tokio::test]
async fn detect_wildcards_on_non_wildcard_zone_is_empty() {
    let real_ip = Ipv4Addr::new(9, 9, 9, 9);
    let mut hosts = HashMap::new();
    hosts.insert("api.example.com".to_string(), host(Some(real_ip), None, None));
    let addr = HermeticZone {
        hosts,
        wildcard: WildcardMode::NxDomain,
        adversarial: AdversarialMode::Normal,
    }
    .serve()
    .await;
    sleep_server().await;

    let resolver = resolver_for(addr);
    let wildcards = detect_wildcards("example.com", &resolver, 5).await;
    assert!(
        wildcards.is_empty(),
        "a non-wildcard zone MUST yield an empty wildcard set (a phantom \
         entry silently drops real subdomains); got {wildcards:?}"
    );

    // And an empty set must filter nothing  -  the real host survives.
    let found = run_bruteforce_with_words(
        "example.com",
        &["api", "zzzgossan-nope-label"],
        resolver,
        Some(wildcards),
        1,
    )
    .await
    .unwrap();
    assert_exact(&found, &["api.example.com"]);
}

/// PRECISION: the learned wildcard set is EXACTLY the synthesised IP  - 
/// no spurious extras (e.g. from the CNAME-chain branch) that would
/// widen the filter and drop unrelated real subdomains.
#[tokio::test]
async fn detect_wildcards_set_is_exactly_the_synthesised_ip() {
    let wild_ip = Ipv4Addr::new(1, 2, 3, 4);
    let addr = HermeticZone {
        hosts: HashMap::new(),
        wildcard: WildcardMode::A(wild_ip),
        adversarial: AdversarialMode::Normal,
    }
    .serve()
    .await;
    sleep_server().await;

    let wildcards = detect_wildcards("example.com", &resolver_for(addr), 5).await;
    let expected: HashSet<IpAddr> = std::iter::once(IpAddr::V4(wild_ip)).collect();
    assert_eq!(
        wildcards, expected,
        "wildcard set must be exactly {{{wild_ip}}}, got {wildcards:?}"
    );
}

/// ADVERSARIAL PRECISION: a broken / hostile resolver (empty answers,
/// NXDOMAIN-with-CNAME, truncated garbage) MUST NOT be misread as
/// "wildcard present". A fabricated wildcard from a flaky upstream would
/// discard every genuine bruteforce finding  -  fail closed to "no
/// wildcard", never crash.
#[tokio::test]
async fn broken_dns_does_not_fabricate_a_wildcard() {
    for mode in [
        AdversarialMode::EmptyAnswer,
        AdversarialMode::NxdomainWithCname,
        AdversarialMode::TruncatedGarbage,
    ] {
        let addr = HermeticZone {
            hosts: HashMap::new(),
            wildcard: WildcardMode::NxDomain,
            adversarial: mode,
        }
        .serve()
        .await;
        sleep_server().await;

        let wildcards = detect_wildcards("example.com", &resolver_for(addr), 4).await;
        assert!(
            wildcards.is_empty(),
            "broken DNS mode {mode:?} must not fabricate a wildcard set, \
             got {wildcards:?}"
        );
    }
}

/// PROVING: recursion finds a deep name under a discovered `dev` label.
#[tokio::test]
async fn recursion_finds_deep_name_under_dev() {
    let mut hosts = HashMap::new();
    hosts.insert(
        "dev.example.com".to_string(),
        host(Some(Ipv4Addr::new(10, 1, 0, 1)), None, None),
    );
    hosts.insert(
        "admin.dev.example.com".to_string(),
        host(Some(Ipv4Addr::new(10, 1, 0, 2)), None, None),
    );
    let addr = HermeticZone {
        hosts,
        wildcard: WildcardMode::NxDomain,
        adversarial: AdversarialMode::Normal,
    }
    .serve()
    .await;
    sleep_server().await;

    let found = run_bruteforce_with_words(
        "example.com",
        &["dev", "admin"],
        resolver_for(addr),
        None,
        2,
    )
    .await
    .unwrap();
    assert_exact(
        &found,
        &["dev.example.com", "admin.dev.example.com"],
    );
}

/// PROVING: `seen` keeps two distinct names; never emits duplicates.
#[tokio::test]
async fn dedup_keeps_distinct_names_and_no_duplicates() {
    let mut hosts = HashMap::new();
    hosts.insert(
        "api.example.com".to_string(),
        host(Some(Ipv4Addr::new(10, 2, 0, 1)), None, None),
    );
    hosts.insert(
        "www.example.com".to_string(),
        host(Some(Ipv4Addr::new(10, 2, 0, 2)), None, None),
    );
    let addr = HermeticZone {
        hosts,
        wildcard: WildcardMode::NxDomain,
        adversarial: AdversarialMode::Normal,
    }
    .serve()
    .await;
    sleep_server().await;

    let found = run_bruteforce_with_words(
        "example.com",
        &["api", "www", "api"],
        resolver_for(addr),
        None,
        1,
    )
    .await
    .unwrap();
    assert_exact(&found, &["api.example.com", "www.example.com"]);
    assert_eq!(
        found.len(),
        found.iter().collect::<HashSet<_>>().len(),
        "no duplicate emissions in result vec"
    );
}

/// PROVING: `GOSSAN_RESOLVER_PORT` routes `build_resolver` to the hermetic server.
#[tokio::test]
async fn gossan_resolver_port_targets_hermetic_server() {
    let mut hosts = HashMap::new();
    hosts.insert(
        "portprobe.example.com".to_string(),
        host(Some(Ipv4Addr::new(10, 3, 0, 1)), None, None),
    );
    let addr = HermeticZone {
        hosts,
        wildcard: WildcardMode::NxDomain,
        adversarial: AdversarialMode::Normal,
    }
    .serve()
    .await;
    sleep_server().await;

    let _env = test_env_lock();
    let _guard = EnvGuard::set("GOSSAN_RESOLVER_PORT", &addr.port().to_string());
    assert_eq!(
        resolver_port(),
        addr.port(),
        "GOSSAN_RESOLVER_PORT must target the hermetic server"
    );

    let found = run_bruteforce_with_words(
        "example.com",
        &["portprobe"],
        gossan_resolver_for(addr),
        None,
        1,
    )
    .await
    .unwrap();
    assert_exact(&found, &["portprobe.example.com"]);
}

/// PROVING: passive source failure does not abort bruteforce (task isolation).
#[tokio::test]
async fn passive_source_failure_does_not_abort_bruteforce() {
    let mut hosts = HashMap::new();
    hosts.insert(
        "api.example.com".to_string(),
        host(Some(Ipv4Addr::new(10, 4, 0, 1)), None, None),
    );
    let addr = HermeticZone {
        hosts,
        wildcard: WildcardMode::NxDomain,
        adversarial: AdversarialMode::Normal,
    }
    .serve()
    .await;
    sleep_server().await;

    let _env = test_env_lock();
    let resolver = gossan_resolver_for(addr);

    let passive: tokio::task::JoinHandle<anyhow::Result<Vec<Target>>> = tokio::spawn(async {
        Err(anyhow::anyhow!("hermetic passive source failure"))
    });
    let bf = tokio::spawn(async move {
        run_bruteforce_with_words("example.com", &["api"], resolver, None, 1).await
    });

    let (passive_res, bf_res) = tokio::join!(passive, bf);
    assert!(passive_res.unwrap().is_err());
    assert_exact(&bf_res.unwrap().unwrap(), &["api.example.com"]);
}

/// ADVERSARIAL: broken/empty DNS responses must not panic or invent hosts.
#[tokio::test]
async fn adversarial_dns_responses_do_not_panic_or_invent() {
    for mode in [
        AdversarialMode::NxdomainWithCname,
        AdversarialMode::EmptyAnswer,
        AdversarialMode::TruncatedGarbage,
    ] {
        let addr = HermeticZone {
            hosts: HashMap::new(),
            wildcard: WildcardMode::NxDomain,
            adversarial: mode,
        }
        .serve()
        .await;
        sleep_server().await;

        let found = run_bruteforce_with_words(
            "example.com",
            &["ghost", "dead"],
            resolver_for(addr),
            None,
            1,
        )
        .await
        .unwrap();
        assert!(
            found.is_empty(),
            "adversarial mode {:?} must not invent hosts, got {found:?}",
            mode
        );
    }
}

struct EnvGuard {
    key: &'static str,
    prev: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let prev = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, prev }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.prev {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}
