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
/// distinct — they're separate vulnerabilities, not duplicates of one.
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
            // exposing a mutator — keeping just the higher-quality
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

    let include_kinds: Vec<secfinding::FindingKind> = include
        .iter()
        .filter_map(|s| secfinding::FindingKind::from_str(s).ok())
        .collect();

    let exclude_kinds: Vec<secfinding::FindingKind> = exclude
        .iter()
        .filter_map(|s| secfinding::FindingKind::from_str(s).ok())
        .collect();

    findings
        .into_iter()
        .filter(|f| {
            // FindingKind is Copy + PartialEq; clone via the public
            // accessor (the field itself is private).
            let k = f.kind();
            if !include_kinds.is_empty() && !include_kinds.contains(&k) {
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
pub fn broadcast(tx: &tokio::sync::mpsc::UnboundedSender<Finding>, findings: &[Finding]) {
    for f in findings {
        if let Err(e) = tx.send(f.clone()) {
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

/// Run a scanner future but treat failures as non-fatal: emit a pipeline
/// finding, broadcast to the live channel, and return an empty `` so
/// the pipeline continues.
#[allow(dead_code)]
// `run_nonfatal` was deleted: the helper was triple-corrupted (return
// type wrong shape, two `gossan_core::` paths missing the trailing
// type) and had no callers anywhere in the workspace. If a future
// pipeline stage needs the "swallow + emit a finding on stage failure"
// pattern, restore from git history (it was the wrapper around stage
// futures that emitted a Severity::High finding tagged `pipeline-error`
// and continued). Re-introducing it requires picking a concrete return
// type — the original used `gossan_core::ScanOutput` which itself was
// retired in the streaming refactor.

// ── Seed target ─────────────────────────────────────────────────────────────

/// Build a seed `Target::Domain` from a user-supplied string.
pub fn seed_target(seed: &str) -> Target {
    use gossan_core::{DiscoverySource, DomainTarget};
    Target::Domain(DomainTarget {
        domain: seed
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/')
            .split('/')
            .next()
            .unwrap_or(seed)
            .to_string(),
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
                .evidence(Evidence::Raw(format!("source={source_label}").into()))
                .build_or_log()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::target::{DiscoverySource, DomainTarget, HostTarget};

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
            // Non-domain targets are silently dropped — only domain
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
}
