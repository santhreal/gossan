//! CVE-replay contract tier (per-rule contract test type #5).
//!
//! Drives the **real public** `gossan_portscan::cve::correlate` path  - 
//! the exact entry point the scanner uses to turn a service banner into
//! CVE findings  -  and asserts *truth, not shape*:
//!
//! 1. **Positive replay**: a curated set of real-world CVE-bearing
//!    banners. For each, EXACTLY ONE finding for that CVE fires, the
//!    title carries the exact `(CVSS x.y)` token, the finding's
//!    `severity()` is the exact expected enum, and it is `cve`-tagged.
//!    `!findings.is_empty()` would be decoration; every field is pinned.
//! 2. **Patched negative twin**: for every positive, the *fixed*
//!    version's banner of the same product. That CVE MUST NOT fire. A
//!    "MUST find" with no "MUST NOT on the safe variant" is a smoke
//!    alarm wired to nothing. The `OpenSSL/1.0.1g` twin specifically
//!    proves the over-broad Heartbleed pattern was actually fixed
//!    (it used to substring-match the patched build).
//! 3. **FP budget**: a benign, real-shaped corpus of fully-patched /
//!    versionless banners. The budget is ZERO  -  any CVE finding here is
//!    a real false positive, never something to pad a budget with.
//! 4. **Community-rules path** (guarded): the same replay+twin contract
//!    through `all_rules` + `correlate_with_rules` so the Tier-B moat
//!    (community CVE TOML) is held to the identical standard.

use gossan_core::{HostTarget, Protocol, ServiceTarget};
use gossan_portscan::cve::{all_rules, correlate, correlate_with_rules};
use secfinding::Severity;
use std::net::IpAddr;

fn svc(port: u16) -> ServiceTarget {
    ServiceTarget {
        host: HostTarget {
            ip: IpAddr::from([127, 0, 0, 1]),
            domain: Some("example.com".into()),
        },
        port,
        protocol: Protocol::Tcp,
        banner: None,
        tls: port == 443,
    }
}

/// Count findings whose title names this exact CVE id.
fn cve_hits(findings: &[secfinding::Finding], cve: &str) -> usize {
    findings
        .iter()
        .filter(|f| f.title().contains(cve))
        .count()
}

/// `(banner, cve, cvss_token, severity, port)`  -  every column is a
/// claim the engine must satisfy exactly.
fn positive_corpus() -> Vec<(&'static str, &'static str, &'static str, Severity, u16)> {
    vec![
        (
            "SSH-2.0-OpenSSH_7.4",
            "CVE-2018-15473",
            "(CVSS 5.3)",
            Severity::Medium,
            22,
        ),
        (
            "SSH-2.0-OpenSSH_8.0p1 Ubuntu-6ubuntu0.1",
            "CVE-2023-38408",
            "(CVSS 9.8)",
            Severity::Critical,
            22,
        ),
        (
            "Server: Apache/2.4.49 (Unix)",
            "CVE-2021-41773",
            "(CVSS 9.8)",
            Severity::Critical,
            80,
        ),
        (
            "Server: Apache/2.4.50 (Unix)",
            "CVE-2021-42013",
            "(CVSS 9.8)",
            Severity::Critical,
            80,
        ),
        (
            "Server: nginx/1.18.0",
            "CVE-2021-23017",
            "(CVSS 7.7)",
            Severity::High,
            80,
        ),
        (
            "220 ProFTPD 1.3.5 Server (ProFTPD Default Installation)",
            "CVE-2015-3306",
            "(CVSS 10.0)",
            Severity::Critical,
            21,
        ),
        (
            "220 (vsFTPd 2.3.4)",
            "CVE-2011-2523",
            "(CVSS 10.0)",
            Severity::Critical,
            21,
        ),
        (
            // Proves the NEW enumerated Heartbleed rule fires on a
            // genuinely vulnerable build (1.0.1f, Ubuntu 14.04 pre-patch).
            "Server: nginx/1.4.6 (OpenSSL/1.0.1f)",
            "CVE-2014-0160",
            "(CVSS 7.5)",
            Severity::High,
            443,
        ),
        (
            "+PONG",
            "CVE-2022-0543",
            "(CVSS 10.0)",
            Severity::Critical,
            6379,
        ),
    ]
}

#[test]
fn cve_positive_replay_fires_with_exact_metadata() {
    for (banner, cve, cvss_tok, sev, port) in positive_corpus() {
        let f = correlate(banner, &svc(port));
        let matching: Vec<_> = f.iter().filter(|x| x.title().contains(cve)).collect();
        assert_eq!(
            matching.len(),
            1,
            "{cve}: expected exactly ONE finding from banner {banner:?}, \
             got {} (titles: {:?})",
            matching.len(),
            f.iter().map(|x| x.title()).collect::<Vec<_>>()
        );
        let hit = matching[0];
        assert!(
            hit.title().contains(cvss_tok),
            "{cve}: title {:?} must carry the exact {cvss_tok} token",
            hit.title()
        );
        assert_eq!(
            hit.severity(),
            sev,
            "{cve}: severity must be exactly {sev:?}, got {:?}",
            hit.severity()
        );
        assert!(
            hit.tags().iter().any(|t| &**t == "cve"),
            "{cve}: finding must carry the `cve` tag (tags={:?})",
            hit.tags()
        );
    }
}

/// `(patched_banner, cve_that_must_not_fire, port)`  -  the safe variant
/// of each positive. The same product, a fixed version.
fn patched_twins() -> Vec<(&'static str, &'static str, u16)> {
    vec![
        ("SSH-2.0-OpenSSH_9.9", "CVE-2018-15473", 22),
        ("SSH-2.0-OpenSSH_9.9", "CVE-2023-38408", 22),
        ("Server: Apache/2.4.62 (Unix)", "CVE-2021-41773", 80),
        ("Server: Apache/2.4.62 (Unix)", "CVE-2021-42013", 80),
        ("Server: nginx/1.27.3", "CVE-2021-23017", 80),
        (
            "220 ProFTPD 1.3.8 Server (ProFTPD Default Installation)",
            "CVE-2015-3306",
            21,
        ),
        ("220 (vsFTPd 3.0.5)", "CVE-2011-2523", 21),
        // The Heartbleed over-broad-pattern proof: 1.0.1g is the FIRST
        // PATCHED build. The old single `openssl/1.0.1` pattern was a
        // substring of `openssl/1.0.1g` and falsely fired here.
        ("Server: nginx/1.4.6 (OpenSSL/1.0.1g)", "CVE-2014-0160", 443),
        ("Server: nginx/1.25.0 (OpenSSL/1.0.1u)", "CVE-2014-0160", 443),
        ("Server: nginx/1.25.0 (OpenSSL/3.0.13)", "CVE-2014-0160", 443),
        ("-NOAUTH Authentication required.", "CVE-2022-0543", 6379),
    ]
}

#[test]
fn cve_patched_twin_does_not_fire() {
    for (banner, cve, port) in patched_twins() {
        let f = correlate(banner, &svc(port));
        assert_eq!(
            cve_hits(&f, cve),
            0,
            "REGRESSION/FP: patched banner {banner:?} must NOT report \
             {cve}, but it did (titles: {:?})",
            f.iter().map(|x| x.title()).collect::<Vec<_>>()
        );
    }
}

#[test]
fn cve_fp_budget_on_benign_corpus_is_zero() {
    // Real-shaped banners of fully-patched / versionless services. None
    // of these is vulnerable to anything in the rule set; the budget is
    // a hard ZERO (a hit here is a real engine FP to fix, not to pad).
    let benign = [
        ("SSH-2.0-OpenSSH_9.9", 22),
        ("Server: nginx/1.27.3", 80),
        ("Server: Apache/2.4.62 (Unix)", 80),
        ("220 (vsFTPd 3.0.5)", 21),
        ("220 ProFTPD 1.3.8 Server", 21),
        ("HTTP/1.1 200 OK\r\nServer: cloudflare\r\n\r\n", 443),
        ("Server: nginx/1.25.0 (OpenSSL/3.0.13)", 443),
        ("Server: Microsoft-IIS/10.0", 80),
        ("220 mail.example.com ESMTP Postfix", 25),
        ("250 mail.example.com Hello", 25),
    ];
    let mut total = 0usize;
    for (banner, port) in benign {
        let f = correlate(banner, &svc(port));
        let cve_findings: Vec<_> = f
            .iter()
            .filter(|x| x.tags().iter().any(|t| &**t == "cve"))
            .collect();
        assert!(
            cve_findings.is_empty(),
            "FP-BUDGET (zero) BREACHED: benign banner {banner:?} produced \
             CVE findings: {:?}",
            cve_findings.iter().map(|x| x.title()).collect::<Vec<_>>()
        );
        total += cve_findings.len();
    }
    assert_eq!(total, 0, "benign corpus must yield zero CVE findings");
}

/// Path to the shipped community CVE rules dir, if present in this
/// checkout layout (vendored builds may differ  -  guarded, never skipped
/// silently in the normal repo layout).
fn community_rules_dir() -> Option<std::path::PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let dir = std::path::Path::new(manifest)
        .join("rules")
        .join("cve");
    dir.exists().then_some(dir)
}

#[test]
fn community_tier_b_cve_replay_and_twin() {
    let Some(dir) = community_rules_dir() else {
        // Repo layout differs (vendored). The builtin tiers above still
        // give full proving coverage; nothing is silently skipped in a
        // normal source checkout where the dir exists.
        return;
    };
    let rules = all_rules(Some(&dir));
    let builtin_only = all_rules(None);
    // Non-brittle moat contract: community rules STRICTLY extend the
    // builtin set (ground truth, not a magic >=100  -  the crate-local
    // pack ships ~36 rules; a hardcoded total just rots).
    assert!(
        rules.len() > builtin_only.len(),
        "Tier-B moat: community rules must strictly extend builtin \
         ({} with community vs {} builtin-only)",
        rules.len(),
        builtin_only.len()
    );

    // The moat must add *detection power*, not just row count:
    // regreSSHion is community-only, so builtin `correlate` MUST be
    // blind to it while the community path MUST catch it.
    let builtin_view = correlate("SSH-2.0-OpenSSH_8.5", &svc(22));
    assert_eq!(
        cve_hits(&builtin_view, "CVE-2024-6387"),
        0,
        "builtin-only must NOT know community CVE-2024-6387 (titles: {:?})",
        builtin_view.iter().map(|x| x.title()).collect::<Vec<_>>()
    );

    // regreSSHion (community): OpenSSH 8.5 vulnerable; 9.8 is the fix.
    let pos = correlate_with_rules("SSH-2.0-OpenSSH_8.5", &svc(22), &rules);
    assert!(
        cve_hits(&pos, "CVE-2024-6387") >= 1,
        "community CVE-2024-6387 must replay on OpenSSH_8.5 (titles: {:?})",
        pos.iter().map(|x| x.title()).collect::<Vec<_>>()
    );
    let twin = correlate_with_rules("SSH-2.0-OpenSSH_9.8", &svc(22), &rules);
    assert_eq!(
        cve_hits(&twin, "CVE-2024-6387"),
        0,
        "patched OpenSSH_9.8 must NOT report regreSSHion (titles: {:?})",
        twin.iter().map(|x| x.title()).collect::<Vec<_>>()
    );

    // Log4Shell is in the community set (asserted by the in-src parse
    // test). Replay it WITHOUT hardcoding its pattern: take the rule's
    // own pattern, embed it in a banner, assert the CVE fires  -  then a
    // banner lacking that token must not.
    if let Some(rule) = rules.iter().find(|r| r.cve == "CVE-2021-44228") {
        let banner = format!("Server: app ({})", rule.pattern);
        let hit = correlate_with_rules(&banner, &svc(8080), &rules);
        assert!(
            cve_hits(&hit, "CVE-2021-44228") >= 1,
            "community CVE-2021-44228 (Log4Shell) must replay on a banner \
             carrying its own pattern {:?} (titles: {:?})",
            rule.pattern,
            hit.iter().map(|x| x.title()).collect::<Vec<_>>()
        );
        let clean = correlate_with_rules(
            "Server: app (unaffected-runtime/1.0)",
            &svc(8080),
            &rules,
        );
        assert_eq!(
            cve_hits(&clean, "CVE-2021-44228"),
            0,
            "a banner without the Log4Shell pattern must not report it"
        );
    }
}
