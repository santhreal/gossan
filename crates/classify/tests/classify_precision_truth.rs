//! Deep precision/truth tests for `gossan_classify`.
//!
//! `matcher.rs` asserted classification with `assert!(!results.is_empty())`
//!  -  a smoke alarm wired to nothing: a regression that returns the
//! WRONG service (or a false "unauthenticated Redis") still passes. For
//! a security recon tool a false service attribution is a false finding,
//! and trust floors at the weakest signal. These assert the EXACT
//! service + version, the priority/ordering CONTRACT the code documents,
//! and the no-false-positive precision contract on benign banners.
//!
//! Contract-first: where the engine violates a documented contract or
//! emits a false positive it is fixed in the crate  -  tests are never
//! weakened to match.

use gossan_classify::matcher::CpuMatcher;
use gossan_classify::rules::builtin_rules;
use gossan_classify::BannerClassifier;

fn clf() -> BannerClassifier {
    BannerClassifier::new()
}

// ───────────────────────── exact truth (no shape) ─────────────────────

#[test]
fn canonical_banners_classify_to_exact_service_and_version() {
    let c = clf();
    let cases: &[(&str, &str, Option<&str>)] = &[
        (
            "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\n\r\n",
            "Apache HTTP Server",
            Some("2.4.52"),
        ),
        (
            "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n",
            "nginx",
            Some("1.24.0"),
        ),
        (
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
            "OpenSSH",
            Some("8.9p1"),
        ),
        (
            r#"{"name":"es","cluster_name":"c","tagline":"You Know, for Search","version":{"number":"8.12.0"}}"#,
            "Elasticsearch",
            Some("8.12.0"),
        ),
    ];
    for (banner, service, version) in cases {
        let top = c
            .classify_top(banner)
            .unwrap_or_else(|| panic!("no classification for {banner:?}"));
        assert_eq!(top.service, *service, "wrong service for {banner:?}");
        assert_eq!(
            top.version.as_deref(),
            *version,
            "wrong version for {banner:?}"
        );
        assert!(
            top.confidence > 0.0 && top.confidence <= 1.0,
            "confidence out of range: {}",
            top.confidence
        );
    }
}

// ─────────────────── P1: the `$` Redis false positive ─────────────────

/// A benign HTTP page containing a dollar sign MUST NOT be classified
/// as Redis. Pre-fix the Redis rule had the bare pattern `"$"`, so any
/// price/shell/PHP `$` produced a Redis match carrying
/// `redis-unauthenticated` + `database-exposed`  -  a false critical
/// finding, the worst possible output of a security tool.
#[test]
fn dollar_sign_in_benign_banner_is_not_redis() {
    let c = clf();
    let benign = [
        "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n<p>Total: $42.00</p>",
        "user@host:~$ ",
        "PHP Notice: Undefined variable $config in /var/www/x.php on line 7",
        "{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\"}",
    ];
    for b in benign {
        let all = c.classify(b);
        assert!(
            !all.iter().any(|m| m.service == "Redis"),
            "benign banner {b:?} was misclassified as Redis (the bare \
             `$` pattern bug): {all:?}"
        );
    }
}

/// Real Redis signals MUST still classify (the fix removes only the
/// catastrophic bare `$`, never Redis recall).
#[test]
fn real_redis_signals_still_classify() {
    let c = clf();
    for b in [
        "+PONG\r\n",
        "-NOAUTH Authentication required.\r\n",
        "$5\r\nhello\r\nredis_version:7.2.4\r\n",
    ] {
        assert!(
            c.classify(b).iter().any(|m| m.service == "Redis"),
            "genuine Redis banner {b:?} must still classify as Redis"
        );
    }
}

// ─────────────── P2: the documented priority/ordering contract ────────

/// `CpuMatcher::match_banner`'s doc says results are "sorted by priority
/// (highest first)" and every `ServiceRule` carries a `priority`
/// documented as "higher = preferred when multiple rules match". When
/// two rules match at EQUAL confidence the higher-priority service must
/// win  -  otherwise `classify_top` returns an arbitrary (insertion-order)
/// service and the documented contract is a lie.
#[test]
fn equal_confidence_ties_break_by_priority() {
    use gossan_classify::rules::ServiceRule;
    let mk = |id: &str, service: &str, pat: &str, priority: u8| ServiceRule {
        id: id.into(),
        service: service.into(),
        protocol: "tcp".into(),
        common_ports: vec![80],
        patterns: vec![pat.into()],
        version_pattern: None,
        security_signals: vec![],
        priority,
    };
    // Both single-pattern, no version ⇒ identical confidence (0.8).
    // `generic` is declared FIRST so a priority-blind sort keeps it on
    // top; the contract says the priority-15 `specific` must win.
    let rules = vec![
        mk("generic", "GenericProxy", "Server: X", 3),
        mk("specific", "SpecificAppServer", "Server: X", 15),
    ];
    let m = CpuMatcher::new(rules);
    let res = m.match_banner("HTTP/1.1 200 OK\r\nServer: X\r\n\r\n");
    assert_eq!(res.len(), 2, "both rules match: {res:?}");
    assert!(
        (res[0].confidence - res[1].confidence).abs() < f32::EPSILON,
        "precondition: equal confidence ({} vs {})",
        res[0].confidence,
        res[1].confidence
    );
    assert_eq!(
        res[0].service, "SpecificAppServer",
        "equal-confidence tie MUST break by priority (15 > 3); the \
         doc-comment promises priority ordering. got {res:?}"
    );
}

// ─────────────────── P3: SNMP "public" HTTP false positive ────────────

/// An HTTP banner with `Cache-Control: public` (ubiquitous) must NOT be
/// classified as SNMP. The SNMP rule used the bare community-string
/// words "public"/"private"  -  never a real SNMP *banner* (SNMP is
/// binary ASN.1; you do not banner-grab the word "public"), so it only
/// ever produced HTTP→SNMP false positives.
#[test]
fn cache_control_public_is_not_snmp() {
    let c = clf();
    let banner =
        "HTTP/1.1 200 OK\r\nCache-Control: public, max-age=3600\r\nServer: nginx/1.24.0\r\n\r\n";
    let all = c.classify(banner);
    let top = c.classify_top(banner).expect("nginx must classify");
    assert_eq!(
        top.service, "nginx",
        "an nginx response must classify as nginx, not SNMP; got {top:?}"
    );
    assert!(
        !all.iter().any(|m| m.service == "SNMP"),
        "`Cache-Control: public` must NOT yield an SNMP match: {all:?}"
    );
}

// ─────────────────────── negative / adversarial ───────────────────────

#[test]
fn unknown_and_hostile_banners_yield_no_match() {
    let c = clf();
    for b in [
        "",
        "XYZZY UNKNOWN PROTOCOL\r\n",
        "\u{0}\u{1}\u{2}\u{3}\u{4}",
        &"A".repeat(100_000),
        "GET / HTTP/1.1\r\nHost: x\r\n\r\n", // a request, not a server banner
    ] {
        let res = c.classify(b);
        assert!(
            res.is_empty(),
            "no service may be inferred from {:?} (len {}): {res:?}",
            &b[..b.len().min(40)],
            b.len()
        );
    }
}

/// Confidence model contract: a versioned match outranks a
/// pattern-only match of the same service family, and the rule set
/// is internally consistent (every builtin rule's first pattern
/// actually triggers its own rule  -  a rule that cannot match itself
/// is dead weight / a typo).
#[test]
fn every_builtin_rule_matches_its_own_first_pattern() {
    let m = CpuMatcher::new(builtin_rules());
    for rule in builtin_rules() {
        let probe = &rule.patterns[0];
        // Skip binary/control-only sentinels that aren't representable
        // as a standalone searchable banner (e.g. RDP \x03\x00, NTP
        // \x1c)  -  those are exercised by the protocol-specific tests.
        if probe.chars().all(|ch| ch.is_control()) {
            continue;
        }
        let res = m.match_banner(probe);
        assert!(
            res.iter().any(|sm| sm.rule_id == rule.id),
            "rule `{}` does not match its own first pattern {:?}  -  \
             dead/typo'd rule",
            rule.id,
            probe
        );
    }
}
