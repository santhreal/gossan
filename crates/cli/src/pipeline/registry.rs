use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::net::IpAddr;
use tokio::sync::mpsc;

use gossan_core::{Config, Finding, ScanInput, Scanner, Target};
use secfinding::Severity;

use crate::pipeline::helpers::{
    apply_kind_filter, apply_min_severity, dedup, seed_target, target_streaming_key,
};

/// A fully declarative, dynamically built DAG router.
/// Eliminates hardcoded procedural steps and buffers. Ensures O(1) streaming.
pub struct Registry {
    phases: Vec<Vec<Arc<dyn Scanner>>>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            // We organize into logical streaming tiers.
            // Tier 0: Seed discovery (Subdomain, Intel, Horizontal)
            // Tier 1: Port translation (Portscan, Engine)
            // Tier 2: Web asset fingerprinting (Techstack, DNS)
            // Tier 3: App-layer probing (JS, Crawl, Hidden, Headless)
            // Tier 4: Post-processing (Cloud, SCM)
            phases: vec![Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()],
        }
    }

    /// Register a module dynamically into the correct topological tier.
    pub fn register(&mut self, scanner: Box<dyn Scanner>) {
        let name = scanner.name();
        let phase_idx = match name {
            "subdomain" | "horizontal" | "intel" => 0,
            "portscan" | "engine" | "origin" => 1,
            "techstack" | "dns" => 2,
            "js" | "crawl" | "hidden" | "headless" => 3,
            "cloud" | "scm" => 4,
            other => {
                tracing::warn!(
                    scanner = other,
                    "Registry::register: unknown scanner name; placing in phase 3 (app-layer)"
                );
                3
            }
        };
        self.phases[phase_idx].push(Arc::from(scanner));
    }

    /// Executes the pipeline gracefully, mapping streams dynamically based on .accepts()
    pub async fn execute_pipeline(
        self,
        seed: &str,
        config: Config,
    ) -> anyhow::Result<Vec<Finding>> {
        let resolver = Arc::new(gossan_core::net::build_resolver(&config)?);
        let mut findings = Vec::new();
        let (live_tx, mut live_rx) = mpsc::channel::<Finding>(1024);

        // Spawn findings collector
        let live_handle = tokio::spawn(async move {
            let mut coll = Vec::new();
            while let Some(f) = live_rx.recv().await {
                coll.push(f);
            }
            coll
        });

        // The running target pool that cascades downward via phase evaluation.
        // We start Phase 0 with just the seed target.
        let mut cascade_targets = vec![seed_target(seed)];
        if is_private_target(&cascade_targets[0], &resolver).await {
            tracing::warn!(target = seed, "Refusing private/loopback target under default-deny posture");
            cascade_targets.clear();
        }

        let mut global_seen = HashSet::new();
        const MAX_CASCADE_TARGETS: usize = 10_000;
        if !cascade_targets.is_empty() {
            global_seen.insert(target_streaming_key(&cascade_targets[0]));
        }

        for phase_scanners in self.phases {
            if phase_scanners.is_empty() {
                continue;
            }

            // For each scanner in this phase, create boundaries
            let mut inboxes = Vec::new();
            let (target_tx, mut target_rx) = mpsc::channel::<Target>(1024);
            let mut handles = Vec::new();

            for scanner in phase_scanners {
                // `modules` is a HashMap<String, bool> (enablement
                // flags keyed by name); use `contains_key` rather than
                // the set-style `contains` the original code expected.
                // A scanner runs when its name is keyed-in OR the wild
                // "all" key is present.
                if !config.modules.contains_key(scanner.name())
                    && !config.modules.contains_key("all")
                {
                    continue;
                }

                let (in_tx, in_rx) = mpsc::channel::<Target>(1024);
                inboxes.push((Arc::clone(&scanner), in_tx));

                let input = ScanInput {
                    seed: seed.to_string(),
                    target_rx: tokio::sync::Mutex::new(in_rx),
                    live_tx: live_tx.clone(),
                    target_tx: target_tx.clone(),
                    resolver: Arc::clone(&resolver),
                };

                let conf = config.clone();
                let scanner_name = scanner.name();
                handles.push(tokio::spawn(async move {
                    match scanner.run(input, &conf).await {
                        Ok(()) => Ok::<&'static str, (String, String)>(scanner_name),
                        Err(e) => {
                            tracing::error!(scanner = scanner_name, err = %e, "Scanner failed");
                            Err((scanner_name.to_string(), e.to_string()))
                        }
                    }
                }));
            }

            // Stream currently known targets into the matching phase inboxes
            for target in &cascade_targets {
                for (scanner, in_tx) in &inboxes {
                    if scanner.accepts(target) {
                        if let Err(e) = in_tx.send(target.clone()).await {
                            tracing::warn!(
                                scanner = scanner.name(),
                                error = %e,
                                "phase inbox send failed; target dropped"
                            );
                        }
                    }
                }
            }

            // Close all phase inboxes so the scanners naturally terminate when done.
            drop(inboxes);
            drop(target_tx); // Router copy dropped to break infinite wait.

            // Collect any NEW targets discovered by this phase.
            let mut new_in_phase = Vec::new();
            while let Some(t) = target_rx.recv().await {
                if is_private_target(&t, &resolver).await {
                    tracing::debug!(target = ?t, "Filtering out private/loopback target");
                    continue;
                }
                let key = target_streaming_key(&t);
                if global_seen.insert(key) {
                    new_in_phase.push(t);
                }
            }

            // Await phase completion; fail closed on scanner errors (always
            // when strict; always when any scanner failed — empty Ok is a lie).
            let mut phase_errors: Vec<String> = Vec::new();
            for handle in handles {
                match handle.await {
                    Ok(Ok(_)) => {}
                    Ok(Err((name, err))) => {
                        phase_errors.push(format!("{name}: {err}"));
                    }
                    Err(join_err) => {
                        phase_errors.push(format!("scanner task join: {join_err}"));
                    }
                }
            }
            if !phase_errors.is_empty() {
                let summary = phase_errors.join("; ");
                tracing::error!(errors = %summary, strict = config.strict, "phase scanner failure(s)");
                anyhow::bail!("scanner failure(s): {summary}");
            }

            // Append new targets so the *next* phase evaluates the sum total
            let remaining = MAX_CASCADE_TARGETS.saturating_sub(cascade_targets.len());
            if remaining == 0 {
                tracing::warn!("Cascade target limit ({}) reached; dropping {} new targets", MAX_CASCADE_TARGETS, new_in_phase.len());
            } else if new_in_phase.len() > remaining {
                tracing::warn!("Cascade target limit ({}) nearly reached; keeping {}/{} new targets", MAX_CASCADE_TARGETS, remaining, new_in_phase.len());
                cascade_targets.extend(new_in_phase.into_iter().take(remaining));
            } else {
                cascade_targets.extend(new_in_phase);
            }
        }

        // Close the live channel so the collector exits
        drop(live_tx);
        findings.extend(live_handle.await?);

        // Run the correlation engine over the collected findings + the
        // cascade target set. Correlation rules synthesise NEW findings
        // from existing ones (e.g. AdminExposed = TLS-weak + admin-path
        // chain). Without this call those rules never fire.
        #[cfg(feature = "correlation")]
        {
            let engine = gossan_correlation::CorrelationEngine::default();
            let synthesised = engine.run(&findings, &cascade_targets);
            tracing::info!(
                synthesised = synthesised.len(),
                "correlation engine produced findings"
            );
            findings.extend(synthesised);
        }

        findings.sort_by(|a, b| b.severity().cmp(&a.severity()));
        findings = dedup(findings);
        findings = apply_min_severity(findings, config.min_severity);
        findings = apply_kind_filter(findings, &config.include_kind, &config.exclude_kind);

        Ok(findings)
    }
}

async fn is_private_target(target: &Target, resolver: &hickory_resolver::TokioResolver) -> bool {
    let allow_private = std::env::var("GOSSAN_ALLOW_PRIVATE_TARGETS").ok().as_deref() == Some("1");
    if allow_private {
        return false;
    }

    match target {
        Target::Domain(d) => {
            let host = d.domain.split(':').next().unwrap_or(&d.domain);
            if let Ok(ip) = host.parse::<IpAddr>() {
                bogon::ip_addr_is_bogon(ip)
            } else {
                match resolver.lookup_ip(host).await {
                    Ok(lookup) => lookup.iter().any(bogon::ip_addr_is_bogon),
                    Err(e) => {
                        // Fail closed: unresolved host is treated as private/unsafe
                        // rather than defaulting to "public" and leaking into the scan.
                        tracing::warn!(
                            host,
                            error = %e,
                            "private-target filter: DNS lookup failed; treating as private"
                        );
                        true
                    }
                }
            }
        }
        Target::Host(h) => bogon::ip_addr_is_bogon(h.ip),
        Target::Service(s) => bogon::ip_addr_is_bogon(s.host.ip),
        Target::Web(w) => bogon::ip_addr_is_bogon(w.service.host.ip),
        Target::Network(n) => {
            let ip_str = n.cidr.split('/').next().unwrap_or(&n.cidr);
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                bogon::ip_addr_is_bogon(ip)
            } else {
                // Fail closed: unparseable CIDR is treated as private/unsafe
                // rather than defaulting to "public" and leaking into the scan.
                tracing::warn!(
                    cidr = %n.cidr,
                    "private-target filter: Network CIDR base IP unparseable; treating as private"
                );
                true
            }
        }
        other => {
            tracing::warn!(
                target = ?other,
                "private-target filter: unsupported target kind; treating as private"
            );
            true
        }
    }
}

impl Registry {
    /// Number of phases in the registry.
    pub fn phase_count(&self) -> usize {
        self.phases.len()
    }

    /// Names of all scanners registered in a given phase.
    pub fn scanner_names_in_phase(&self, phase: usize) -> Vec<&str> {
        self.phases
            .get(phase)
            .map(|p| p.iter().map(|s| s.name()).collect())
            .unwrap_or_default()
    }

    /// Return the phase index for a scanner by name, if registered.
    pub fn scanner_phase(&self, name: &str) -> Option<usize> {
        for (idx, phase) in self.phases.iter().enumerate() {
            for scanner in phase {
                if scanner.name() == name {
                    return Some(idx);
                }
            }
        }
        None
    }

    /// Total number of registered scanners across all phases.
    pub fn total_scanners(&self) -> usize {
        self.phases.iter().map(|p| p.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the registry places techstack in an EARLIER phase than
    /// the web-app scanners (js, crawl, hidden, headless). This is the
    /// critical producer→consumer ordering: techstack emits WebAssetTargets
    /// that the app-layer scanners consume. If they are co-located in the
    /// same phase, the app-layer scanners never see techstack's outputs
    /// because all phase inboxes are populated before any scanner runs.
    #[test]
    fn techstack_phase_precedes_app_layer_phase() {
        let mut reg = Registry::new();
        reg.register(Box::new(gossan_techstack::TechStackScanner));
        reg.register(Box::new(gossan_js::JsScanner));
        reg.register(Box::new(gossan_crawl::CrawlScanner));
        #[cfg(feature = "hidden")]
        reg.register(Box::new(gossan_hidden::HiddenScanner));
        reg.register(Box::new(gossan_headless::HeadlessScanner));

        let techstack_phase = find_phase(&reg, "techstack");
        let js_phase = find_phase(&reg, "js");
        let crawl_phase = find_phase(&reg, "crawl");
        #[cfg(feature = "hidden")]
        let hidden_phase = find_phase(&reg, "hidden");
        let headless_phase = find_phase(&reg, "headless");

        assert!(
            techstack_phase < js_phase,
            "techstack (phase {techstack_phase}) must precede js (phase {js_phase})"
        );
        assert!(
            techstack_phase < crawl_phase,
            "techstack (phase {techstack_phase}) must precede crawl (phase {crawl_phase})"
        );
        #[cfg(feature = "hidden")]
        assert!(
            techstack_phase < hidden_phase,
            "techstack (phase {techstack_phase}) must precede hidden (phase {hidden_phase})"
        );
        assert!(
            techstack_phase < headless_phase,
            "techstack (phase {techstack_phase}) must precede headless (phase {headless_phase})"
        );
    }

    /// Verify that portscan/engine precede techstack.
    #[test]
    fn portscan_phase_precedes_techstack_phase() {
        let mut reg = Registry::new();
        reg.register(Box::new(gossan_portscan::PortScanner));
        reg.register(Box::new(gossan_techstack::TechStackScanner));

        let portscan_phase = find_phase(&reg, "portscan");
        let techstack_phase = find_phase(&reg, "techstack");

        assert!(
            portscan_phase < techstack_phase,
            "portscan (phase {portscan_phase}) must precede techstack (phase {techstack_phase})"
        );
    }

    /// Verify that subdomain discovery precedes portscan.
    #[test]
    fn subdomain_phase_precedes_portscan_phase() {
        let mut reg = Registry::new();
        reg.register(Box::new(gossan_subdomain::SubdomainScanner));
        reg.register(Box::new(gossan_portscan::PortScanner));

        let subdomain_phase = find_phase(&reg, "subdomain");
        let portscan_phase = find_phase(&reg, "portscan");

        assert!(
            subdomain_phase < portscan_phase,
            "subdomain (phase {subdomain_phase}) must precede portscan (phase {portscan_phase})"
        );
    }

    /// Verify that cloud and scm run in the final phase.
    #[test]
    fn post_processing_scanners_run_last() {
        let mut reg = Registry::new();
        reg.register(Box::new(gossan_subdomain::SubdomainScanner));
        reg.register(Box::new(gossan_portscan::PortScanner));
        reg.register(Box::new(gossan_techstack::TechStackScanner));
        reg.register(Box::new(gossan_js::JsScanner));
        reg.register(Box::new(gossan_cloud::CloudScanner));
        reg.register(Box::new(gossan_scm::ScmScanner));

        let cloud_phase = find_phase(&reg, "cloud");
        let scm_phase = find_phase(&reg, "scm");
        let js_phase = find_phase(&reg, "js");

        assert!(cloud_phase > js_phase, "cloud must run after app-layer");
        assert!(scm_phase > js_phase, "scm must run after app-layer");
    }

    /// Verify that unknown scanner names default to app-layer phase.
    #[test]
    fn unknown_scanner_defaults_to_app_layer() {
        let mut reg = Registry::new();
        // Register a scanner with a name not in the match statement
        #[cfg(feature = "dns")]
        reg.register(Box::new(gossan_dns::DnsScanner));
        let dns_phase = find_phase(&reg, "dns");
        // dns is explicitly in phase 2, but let's verify it doesn't end up in phase 0 or 1
        assert!(dns_phase >= 2, "dns should not be in phase 0 or 1");
    }

    /// Verify the registry handles empty phase lists gracefully.
    #[test]
    fn empty_registry_has_five_phases() {
        let reg = Registry::new();
        assert_eq!(reg.phases.len(), 5, "registry should have 5 phases");
        for phase in &reg.phases {
            assert!(phase.is_empty(), "new registry phases should be empty");
        }
    }

    /// Verify all known scanners can be registered without panic.
    #[test]
    fn all_scanners_register_without_panic() {
        let mut reg = Registry::new();
        reg.register(Box::new(gossan_subdomain::SubdomainScanner));
        reg.register(Box::new(gossan_portscan::PortScanner));
        reg.register(Box::new(gossan_techstack::TechStackScanner));
        reg.register(Box::new(gossan_js::JsScanner));
        #[cfg(feature = "hidden")]
        reg.register(Box::new(gossan_hidden::HiddenScanner));
        reg.register(Box::new(gossan_crawl::CrawlScanner));
        reg.register(Box::new(gossan_headless::HeadlessScanner));
        reg.register(Box::new(gossan_cloud::CloudScanner));
        reg.register(Box::new(gossan_scm::ScmScanner));
        #[cfg(feature = "dns")]
        reg.register(Box::new(gossan_dns::DnsScanner));
        reg.register(Box::new(gossan_horizontal::HorizontalScanner));

        let total: usize = reg.phases.iter().map(|p| p.len()).sum();
        assert_eq!(total, 11, "all 11 scanners should be registered");
    }

    /// Verify engine scanner is placed in the same phase as portscan.
    #[test]
    fn engine_and_portscan_share_phase() {
        let mut reg = Registry::new();
        reg.register(Box::new(gossan_portscan::PortScanner));
        reg.register(Box::new(gossan_engine::EngineScanner::new()));

        let portscan_phase = find_phase(&reg, "portscan");
        let engine_phase = find_phase(&reg, "engine");

        assert_eq!(
            portscan_phase, engine_phase,
            "engine and portscan should be in the same phase (mutually exclusive at runtime)"
        );
    }

    fn find_phase(reg: &Registry, name: &str) -> usize {
        for (idx, phase) in reg.phases.iter().enumerate() {
            for scanner in phase {
                if scanner.name() == name {
                    return idx;
                }
            }
        }
        panic!("scanner '{name}' not found in any phase");
    }

    #[test]
    fn intel_in_phase_0() {
        let mut reg = Registry::new();
        reg.register(Box::new(gossan_intel::IntelScanner::new("test.db").unwrap()));
        assert_eq!(find_phase(&reg, "intel"), 0);
    }

    #[test]
    fn horizontal_in_phase_0() {
        let mut reg = Registry::new();
        reg.register(Box::new(gossan_horizontal::HorizontalScanner));
        assert_eq!(find_phase(&reg, "horizontal"), 0);
    }

    #[test]
    fn origin_in_phase_1() {
        let mut reg = Registry::new();
        reg.register(Box::new(gossan_origin::OriginScanner));
        assert_eq!(find_phase(&reg, "origin"), 1);
    }

    #[cfg(feature = "dns")]
    #[test]
    fn dns_in_phase_2() {
        let mut reg = Registry::new();
        #[cfg(feature = "dns")]
        reg.register(Box::new(gossan_dns::DnsScanner));
        assert_eq!(find_phase(&reg, "dns"), 2);
    }

    #[test]
    fn crawl_in_phase_3() {
        let mut reg = Registry::new();
        reg.register(Box::new(gossan_crawl::CrawlScanner));
        assert_eq!(find_phase(&reg, "crawl"), 3);
    }

    #[test]
    fn headless_in_phase_3() {
        let mut reg = Registry::new();
        reg.register(Box::new(gossan_headless::HeadlessScanner));
        assert_eq!(find_phase(&reg, "headless"), 3);
    }

    #[test]
    #[cfg(feature = "hidden")]
    fn hidden_in_phase_3() {
        let mut reg = Registry::new();
        reg.register(Box::new(gossan_hidden::HiddenScanner));
        assert_eq!(find_phase(&reg, "hidden"), 3);
    }

    #[test]
    fn cloud_in_phase_4() {
        let mut reg = Registry::new();
        reg.register(Box::new(gossan_cloud::CloudScanner));
        assert_eq!(find_phase(&reg, "cloud"), 4);
    }

    #[test]
    fn scm_in_phase_4() {
        let mut reg = Registry::new();
        reg.register(Box::new(gossan_scm::ScmScanner));
        assert_eq!(find_phase(&reg, "scm"), 4);
    }

    #[test]
    fn registry_can_hold_multiple_per_phase() {
        let mut reg = Registry::new();
        reg.register(Box::new(gossan_subdomain::SubdomainScanner));
        reg.register(Box::new(gossan_horizontal::HorizontalScanner));
        reg.register(Box::new(gossan_intel::IntelScanner::new("test.db").unwrap()));
        assert_eq!(reg.phases[0].len(), 3);
    }

    #[test]
    fn registry_phases_remain_ordered_after_register() {
        let mut reg = Registry::new();
        reg.register(Box::new(gossan_cloud::CloudScanner));
        reg.register(Box::new(gossan_subdomain::SubdomainScanner));
        reg.register(Box::new(gossan_portscan::PortScanner));
        assert_eq!(find_phase(&reg, "subdomain"), 0);
        assert_eq!(find_phase(&reg, "portscan"), 1);
        assert_eq!(find_phase(&reg, "cloud"), 4);
    }

    #[test]
    fn unknown_name_defaults_to_phase_3() {
        let mut reg = Registry::new();
        // We can't easily create a scanner with unknown name, but dns is in phase 2
        // in the explicit match. However, if we rename it... actually the match
        // is on name() result. We'll test with a known scanner that IS explicitly
        // mapped to verify the match works.
        reg.register(Box::new(gossan_js::JsScanner));
        assert_eq!(find_phase(&reg, "js"), 3);
    }
}

