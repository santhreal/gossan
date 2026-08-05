//! Shared pipeline helpers.
//!
//! Common utilities used by both [`super::full`] and [`super::module`] pipeline
//! modes: hashing, deduplication, severity filtering, live broadcast, and
//! progress bar construction.

use gossan_core::Target;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use secfinding::{Finding, Severity};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

// ── Target hashing ──────────────────────────────────────────────────────────

/// Produce a stable u64 hash for a target, suitable for dedup / streaming keys.
pub fn target_streaming_key(target: &Target) -> u64 {
    use hashkit::wyhash;
    match target {
        Target::Domain(d) => wyhash::hash(d.domain.as_bytes(), 0),
        Target::Host(h) => {
            let mut h_val = match h.ip {
                std::net::IpAddr::V4(v4) => wyhash::hash(&v4.octets(), 0),
                std::net::IpAddr::V6(v6) => wyhash::hash(&v6.octets(), 0),
            };
            if let Some(dom) = &h.domain {
                h_val = wyhash::hash(dom.as_bytes(), h_val);
            }
            h_val
        }
        Target::Service(s) => {
            let mut h_val = match s.host.ip {
                std::net::IpAddr::V4(v4) => wyhash::hash(&v4.octets(), 0),
                std::net::IpAddr::V6(v6) => wyhash::hash(&v6.octets(), 0),
            };
            h_val = wyhash::hash(&s.port.to_le_bytes(), h_val);
            if let Some(dom) = &s.host.domain {
                h_val = wyhash::hash(dom.as_bytes(), h_val);
            }
            h_val
        }
        Target::Web(w) => wyhash::hash(w.url.as_str().as_bytes(), 0),
        Target::Network(n) => wyhash::hash(n.cidr.as_bytes(), 0),
        Target::Repository(r) => wyhash::hash(r.url.as_str().as_bytes(), 0),
        Target::InternalPackage(p) => wyhash::hash(p.name.as_bytes(), 0),
        _ => {
            let repr = format!("{:?}", target);
            wyhash::hash(repr.as_bytes(), 0)
        }
    }
}

/// Compute a semantic identity key for deduplication.
///
/// Identity = `kind + target + title + detail + evidence` (title/target
/// case-insensitive). Two SQL-injection findings with different `detail`
/// (e.g. different parameter names) or different evidence remain
/// distinct (they're separate vulnerabilities, not duplicates of one).
/// The same finding emitted twice by the same scanner with identical
/// payload will collapse.
pub fn finding_dedup_key(f: &Finding) -> u64 {
    use hashkit::wyhash;
    let mut h = wyhash::hash(format!("{:?}", f.kind()).as_bytes(), 0);
    h = wyhash::hash(f.target().to_ascii_lowercase().as_bytes(), h);
    h = wyhash::hash(f.title().to_ascii_lowercase().as_bytes(), h);
    h = wyhash::hash(f.detail().as_bytes(), h);
    h = wyhash::hash(format!("{:?}", f.evidence()).as_bytes(), h);
    h
}

/// Compute a structural hash over a finding for exact deduplication.
///
/// Use this when you need to distinguish findings with the same title
/// but genuinely different evidence (e.g. two SQL injections on different
/// parameters).
pub fn finding_dedup_hash(f: &Finding) -> u64 {
    use hashkit::wyhash;
    let mut h = wyhash::hash(f.target().as_bytes(), 0);
    h = wyhash::hash(f.title().as_bytes(), h);
    h = wyhash::hash(f.detail().as_bytes(), h);
    h = wyhash::hash(format!("{:?}", f.evidence()).as_bytes(), h);
    if let Some(hint) = f.exploit_hint() {
        h = wyhash::hash(hint.as_bytes(), h);
    }
    h
}

/// Remove semantically duplicate findings, merging cross-scanner duplicates.
///
/// When two findings match on `kind + target + title`, keeps the one with
/// higher severity and more evidence. Tags are merged from both.
pub fn dedup(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen: HashMap<u64, usize> = HashMap::new();
    let mut result: Vec<Finding> = Vec::with_capacity(findings.len());

    for f in findings {
        let key = finding_dedup_key(&f);
        if let Some(&existing_idx) = seen.get(&key) {
            let existing = &result[existing_idx];
            // Keep the better finding: higher severity wins, then more
            // evidence. (Historically this branch also merged the
            // dropped finding's tags into the kept one, but the
            // secfinding refactor made `Finding.tags` private without
            // exposing a mutator, keeping just the higher-quality
            // finding is correct semantics, just loses the dropped
            // finding's unique tags. If tag-merging matters, the
            // upstream fix is `pub fn tags_mut(&mut self)` on
            // secfinding::Finding.)
            let should_replace = f.severity() > existing.severity()
                || (f.severity() == existing.severity()
                    && f.evidence().len() > existing.evidence().len());
            if should_replace {
                result[existing_idx] = f;
            }
        } else {
            seen.insert(key, result.len());
            result.push(f);
        }
    }

    result
}

/// Filter findings to only those meeting a minimum severity.
pub fn apply_min_severity(findings: Vec<Finding>, min: Option<Severity>) -> Vec<Finding> {
    match min {
        None => findings,
        Some(min) => findings
            .into_iter()
            .filter(|f| f.severity() >= min)
            .collect(),
    }
}

/// Filter findings by `FindingKind` include/exclude lists.
///
/// - `include`: if non-empty, only keep findings matching these kinds.
/// - `exclude`: remove findings matching these kinds.
///
/// Kind strings are parsed case-insensitively via `FindingKind::from_str`.
pub fn apply_kind_filter(
    findings: Vec<Finding>,
    include: &[String],
    exclude: &[String],
) -> Vec<Finding> {
    use std::str::FromStr;

    if include.is_empty() && exclude.is_empty() {
        return findings;
    }

    let mut include_kinds: Vec<secfinding::FindingKind> = Vec::with_capacity(include.len());
    for s in include {
        match secfinding::FindingKind::from_str(s) {
            Ok(k) => include_kinds.push(k),
            Err(_) => tracing::warn!(
                "ignoring unparseable --include-kind value: {s}"
            ),
        }
    }

    // Non-empty include that parsed to nothing must not fail open (pass all).
    let include_active = !include.is_empty();
    if include_active && include_kinds.is_empty() {
        tracing::warn!(
            "all --include-kind values were unparseable; emitting zero findings (fail-closed)"
        );
        return Vec::new();
    }

    let mut exclude_kinds: Vec<secfinding::FindingKind> = Vec::with_capacity(exclude.len());
    for s in exclude {
        match secfinding::FindingKind::from_str(s) {
            Ok(k) => exclude_kinds.push(k),
            Err(_) => tracing::warn!(
                "ignoring unparseable --exclude-kind value: {s}"
            ),
        }
    }

    findings
        .into_iter()
        .filter(|f| {
            // FindingKind is Copy + PartialEq; clone via the public
            // accessor (the field itself is private).
            let k = f.kind();
            if include_active && !include_kinds.contains(&k) {
                return false;
            }
            if exclude_kinds.contains(&k) {
                return false;
            }
            true
        })
        .collect()
}


// ── Web asset dedup ─────────────────────────────────────────────────────────

/// Deduplicate structurally identical web assets to prevent scanning the same
/// CDN edge 50 times.
pub fn dedup_web_assets(targets: Vec<Target>) -> Vec<Target> {
    let mut seen = HashSet::new();
    targets
        .into_iter()
        .filter(|t| {
            if let Target::Web(w) = t {
                let ip = w.service.host.ip;
                let port = w.service.port;
                let hash = w.body_hash.as_deref().unwrap_or("nohash");
                let key = format!("{}:{}-{}-{}", ip, port, w.status, hash);
                seen.insert(key)
            } else {
                true
            }
        })
        .collect()
}

// ── Live broadcast ──────────────────────────────────────────────────────────

/// Send findings to the live channel for real-time operator output.
pub fn broadcast(tx: &tokio::sync::mpsc::Sender<Finding>, findings: &[Finding]) {
    for f in findings {
        if let Err(e) = tx.try_send(f.clone()) {
            tracing::warn!(error = ?e, "live channel send failed, dropping finding");
        }
    }
}

// ── Progress bar ────────────────────────────────────────────────────────────

/// Create a styled spinner progress bar.
pub fn spinner(mp: &MultiProgress, msg: &str) -> ProgressBar {
    let pb = mp.add(ProgressBar::new_spinner());
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap_or(ProgressStyle::default_spinner())
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", " "]),
    );
    pb.enable_steady_tick(Duration::from_millis(80));
    pb.set_message(msg.to_string());
    pb
}

/// Mark a stage as complete with a checkmark.
pub fn finish(pb: &ProgressBar, msg: &str) {
    pb.set_style(
        ProgressStyle::with_template("  \x1b[32m✓\x1b[0m {msg}")
            .unwrap_or(ProgressStyle::default_spinner()),
    );
    pb.finish_with_message(msg.to_string());
}

// ── Stage runner ────────────────────────────────────────────────────────────
// `run_nonfatal` was removed: the helper had no callers and a broken return
// type after the streaming refactor retired `gossan_core::ScanOutput`.
// Restore from git history if a future pipeline stage needs the
// "swallow + emit Severity::High finding tagged `pipeline-error`" pattern.

// ── Seed target ─────────────────────────────────────────────────────────────

/// Build a seed `Target::Domain` from a user-supplied string.
pub fn seed_target(seed: &str) -> Target {
    use gossan_core::{DiscoverySource, DomainTarget, HostTarget};
    use std::net::IpAddr;

    let host = seed
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .split('/')
        .next()
        .unwrap_or(seed)
        .to_string();

    // Strip optional :port for IP parse (keep Domain path for hostnames with ports).
    // Also accept bracketed IPv6 URL forms like [2001:db8::1].
    let host_for_ip = host.split('%').next().unwrap_or(&host);
    let host_for_ip = host_for_ip.trim_start_matches('[').trim_end_matches(']');
    let host_for_ip = match host_for_ip.rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) && !h.contains(':') => h,
        _ => host_for_ip,
    };

    if let Ok(ip) = host_for_ip.parse::<IpAddr>() {
        return Target::Host(HostTarget {
            ip,
            domain: None,
        });
    }

    Target::Domain(DomainTarget {
        domain: host,
        source: DiscoverySource::Seed,
    })
}

// ── Subdomain findings ──────────────────────────────────────────────────────

/// Convert discovered domain targets into Info-severity findings.
pub fn make_subdomain_discovery_findings(targets: &[Target]) -> Vec<Finding> {
    use secfinding::Evidence;
    targets
        .iter()
        .filter_map(|target| {
            let Target::Domain(d) = target else {
                return None;
            };
            let source_label = format!("{:?}", d.source)
                .to_lowercase()
                .replace("discoverysource::", "");
            Finding::builder("subdomain", d.domain.as_str(), Severity::Info)
                .title(format!("Subdomain: {}", d.domain))
                .detail(format!("Discovered via {}", source_label))
                .kind(secfinding::FindingKind::InfoDisclosure)
                .tag("subdomain")
                .tag("discovery")
                .evidence(Evidence::raw(format!("source={source_label}")))
                .build_or_log()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::target::{DiscoverySource, DomainTarget, HostTarget, NetworkTarget};
    use secfinding::Evidence;

    #[test]
    fn make_subdomain_discovery_findings_emits_one_per_domain() {
        let targets = vec![
            Target::Domain(DomainTarget {
                domain: "a.example.com".into(),
                source: DiscoverySource::CertificateTransparency,
            }),
            Target::Domain(DomainTarget {
                domain: "b.example.com".into(),
                source: DiscoverySource::DnsBruteforce,
            }),
            // Non-domain targets are silently dropped, only domain
            // discoveries become findings here.
            Target::Host(HostTarget {
                ip: "1.1.1.1".parse().unwrap(),
                domain: None,
            }),
        ];
        let findings = make_subdomain_discovery_findings(&targets);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].target(), "a.example.com");
        assert_eq!(findings[0].severity(), Severity::Info);
        assert!(findings[0].title().starts_with("Subdomain: "));
        assert!(findings[1].detail().contains("dnsbruteforce"));
    }

    #[test]
    fn target_streaming_key_domain_stable() {
        let t1 = seed_target("example.com");
        let t2 = seed_target("example.com");
        assert_eq!(target_streaming_key(&t1), target_streaming_key(&t2));
    }

    #[test]
    fn target_streaming_key_domain_different() {
        let t1 = seed_target("a.com");
        let t2 = seed_target("b.com");
        assert_ne!(target_streaming_key(&t1), target_streaming_key(&t2));
    }

    #[test]
    fn target_streaming_key_host_ip_only() {
        use std::net::{IpAddr, Ipv4Addr};
        let t = Target::Host(HostTarget {
            ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            domain: None,
        });
        let key1 = target_streaming_key(&t);
        let key2 = target_streaming_key(&t);
        assert_eq!(key1, key2);
    }

    #[test]
    fn target_streaming_key_host_with_domain() {
        use std::net::{IpAddr, Ipv4Addr};
        let t1 = Target::Host(HostTarget {
            ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            domain: Some("a.com".into()),
        });
        let t2 = Target::Host(HostTarget {
            ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            domain: Some("b.com".into()),
        });
        assert_ne!(target_streaming_key(&t1), target_streaming_key(&t2));
    }

    #[test]
    fn target_streaming_key_network() {
        let t1 = Target::Network(NetworkTarget {
            cidr: "10.0.0.0/24".into(),
            source: DiscoverySource::Seed,
        });
        let t2 = Target::Network(NetworkTarget {
            cidr: "10.0.0.0/24".into(),
            source: DiscoverySource::Seed,
        });
        assert_eq!(target_streaming_key(&t1), target_streaming_key(&t2));
    }

    #[test]
    fn seed_target_strips_http() {
        let t = seed_target("http://example.com");
        match t {
            Target::Domain(d) => assert_eq!(d.domain, "example.com"),
            _ => panic!("expected Domain"),
        }
    }

    #[test]
    fn seed_target_strips_https() {
        let t = seed_target("https://example.com");
        match t {
            Target::Domain(d) => assert_eq!(d.domain, "example.com"),
            _ => panic!("expected Domain"),
        }
    }

    #[test]
    fn seed_target_strips_trailing_slash() {
        let t = seed_target("example.com/");
        match t {
            Target::Domain(d) => assert_eq!(d.domain, "example.com"),
            _ => panic!("expected Domain"),
        }
    }

    #[test]
    fn seed_target_strips_path() {
        let t = seed_target("example.com/path/to/page");
        match t {
            Target::Domain(d) => assert_eq!(d.domain, "example.com"),
            _ => panic!("expected Domain"),
        }
    }

    #[test]
    fn dedup_empty_vec() {
        let r = dedup(vec![]);
        assert!(r.is_empty());
    }

    #[test]
    fn dedup_single_finding() {
        let f = Finding::builder("test", "example.com", Severity::High)
            .title("XSS")
            .detail("reflected")
            .build()
            .unwrap();
        let r = dedup(vec![f.clone()]);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn dedup_replaces_with_higher_severity() {
        let low = Finding::builder("test", "example.com", Severity::Low)
            .title("Same")
            .detail("detail")
            .build()
            .unwrap();
        let high = Finding::builder("test", "example.com", Severity::High)
            .title("Same")
            .detail("detail")
            .build()
            .unwrap();
        let r = dedup(vec![low, high]);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].severity(), Severity::High);
    }

    #[test]
    fn dedup_keeps_first_when_equal_severity() {
        let a = Finding::builder("test", "example.com", Severity::Medium)
            .title("Same")
            .detail("detail")
            .build()
            .unwrap();
        let b = Finding::builder("test", "example.com", Severity::Medium)
            .title("Same")
            .detail("detail")
            .build()
            .unwrap();
        let r = dedup(vec![a.clone(), b]);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn apply_min_severity_none_passes_all() {
        let findings = vec![
            Finding::builder("test", "example.com", Severity::Info).title("i").detail("d").build().unwrap(),
            Finding::builder("test", "example.com", Severity::High).title("h").detail("d").build().unwrap(),
        ];
        let r = apply_min_severity(findings, None);
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn apply_min_severity_filters_out_lower() {
        let findings = vec![
            Finding::builder("test", "example.com", Severity::Info).title("i").detail("d").build().unwrap(),
            Finding::builder("test", "example.com", Severity::Low).title("l").detail("d").build().unwrap(),
            Finding::builder("test", "example.com", Severity::High).title("h").detail("d").build().unwrap(),
        ];
        let r = apply_min_severity(findings, Some(Severity::Low));
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn apply_min_severity_critical_only() {
        let findings = vec![
            Finding::builder("test", "example.com", Severity::High).title("h").detail("d").build().unwrap(),
            Finding::builder("test", "example.com", Severity::Critical).title("c").detail("d").build().unwrap(),
        ];
        let r = apply_min_severity(findings, Some(Severity::Critical));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].severity(), Severity::Critical);
    }

    #[test]
    fn apply_kind_filter_empty_lists_pass_all() {
        let findings = vec![
            Finding::builder("test", "example.com", Severity::Info)
                .title("t")
                .detail("d")
                .kind(secfinding::FindingKind::Vulnerability)
                .build()
                .unwrap(),
        ];
        let r = apply_kind_filter(findings, &[], &[]);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn apply_kind_filter_include_only_matching() {
        let findings = vec![
            Finding::builder("test", "example.com", Severity::Info)
                .title("t")
                .detail("d")
                .kind(secfinding::FindingKind::Vulnerability)
                .build()
                .unwrap(),
            Finding::builder("test", "example.com", Severity::Info)
                .title("t2")
                .detail("d")
                .kind(secfinding::FindingKind::Exposure)
                .build()
                .unwrap(),
        ];
        let r = apply_kind_filter(findings, &["vulnerability".to_string()], &[]);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind(), secfinding::FindingKind::Vulnerability);
    }

    #[test]
    fn apply_kind_filter_exclude_matching() {
        let findings = vec![
            Finding::builder("test", "example.com", Severity::Info)
                .title("t")
                .detail("d")
                .kind(secfinding::FindingKind::Vulnerability)
                .build()
                .unwrap(),
            Finding::builder("test", "example.com", Severity::Info)
                .title("t2")
                .detail("d")
                .kind(secfinding::FindingKind::Exposure)
                .build()
                .unwrap(),
        ];
        let r = apply_kind_filter(findings, &[], &["vulnerability".to_string()]);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind(), secfinding::FindingKind::Exposure);
    }

        #[test]
    fn apply_kind_filter_all_invalid_include_yields_empty() {
        let findings = vec![
            Finding::builder("t", "h", Severity::Info)
                .title("a")
                .detail("d")
                .kind(secfinding::FindingKind::Exposure)
                .build()
                .unwrap(),
        ];
        let r = apply_kind_filter(findings, &["not-a-real-kind".to_string()], &[]);
        assert!(
            r.is_empty(),
            "invalid-only --include-kind must fail closed (empty), not pass all"
        );
    }

#[test]
    fn apply_kind_filter_case_insensitive() {
        let findings = vec![
            Finding::builder("test", "example.com", Severity::Info)
                .title("t")
                .detail("d")
                .kind(secfinding::FindingKind::Vulnerability)
                .build()
                .unwrap(),
        ];
        let r = apply_kind_filter(findings, &["VULNERABILITY".to_string()], &[]);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn dedup_web_assets_empty() {
        let r = dedup_web_assets(vec![]);
        assert!(r.is_empty());
    }

    #[test]
    fn dedup_web_assets_non_web_passthrough() {
        let t = Target::Domain(DomainTarget {
            domain: "example.com".into(),
            source: DiscoverySource::Seed,
        });
        let r = dedup_web_assets(vec![t.clone()]);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn finding_dedup_key_stable() {
        let f = Finding::builder("test", "example.com", Severity::High)
            .title("XSS")
            .detail("reflected")
            .build()
            .unwrap();
        let k1 = finding_dedup_key(&f);
        let k2 = finding_dedup_key(&f);
        assert_eq!(k1, k2);
    }

    #[test]
    fn finding_dedup_key_different_targets() {
        let f1 = Finding::builder("test", "a.com", Severity::High)
            .title("XSS")
            .detail("reflected")
            .build()
            .unwrap();
        let f2 = Finding::builder("test", "b.com", Severity::High)
            .title("XSS")
            .detail("reflected")
            .build()
            .unwrap();
        assert_ne!(finding_dedup_key(&f1), finding_dedup_key(&f2));
    }

    #[test]
    fn finding_dedup_hash_includes_evidence() {
        let f1 = Finding::builder("test", "example.com", Severity::High)
            .title("XSS")
            .detail("reflected")
            .evidence(Evidence::raw("param=id"))
            .build()
            .unwrap();
        let f2 = Finding::builder("test", "example.com", Severity::High)
            .title("XSS")
            .detail("reflected")
            .evidence(Evidence::raw("param=name"))
            .build()
            .unwrap();
        assert_ne!(finding_dedup_hash(&f1), finding_dedup_hash(&f2));
    }
}

#[cfg(test)]
mod seed_target_tests {
    use super::*;

    #[test]
    fn seed_target_ip_literal_emits_host() {
        let t = seed_target("8.8.8.8");
        match t {
            Target::Host(h) => assert_eq!(h.ip.to_string(), "8.8.8.8"),
            other => panic!("expected Host, got {other:?}"),
        }
    }

    #[test]
    fn seed_target_ipv6_bracket_emits_host() {
        let t = seed_target("[2001:db8::1]");
        match t {
            Target::Host(h) => assert_eq!(h.ip.to_string(), "2001:db8::1"),
            other => panic!("expected Host, got {other:?}"),
        }
    }

    #[test]
    fn seed_target_hostname_emits_domain() {
        let t = seed_target("example.com");
        match t {
            Target::Domain(d) => assert_eq!(d.domain, "example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
    }
}
