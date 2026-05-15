use std::collections::{HashMap, HashSet};
use std::sync::Arc;
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
            // Tier 1: Port translation (Portscan, Synscan)
            // Tier 2: App layer fingerprinting (Techstack, DNS, JS, Crawler)
            // Tier 3: Post-processing (Cloud, SCM)
            phases: vec![Vec::new(), Vec::new(), Vec::new(), Vec::new()],
        }
    }

    /// Register a module dynamically into the correct topological tier.
    pub fn register(&mut self, scanner: Box<dyn Scanner>) {
        let name = scanner.name();
        let phase_idx = match name {
            "subdomain" | "horizontal" | "intel" => 0,
            "portscan" | "engine" => 1,
            "techstack" | "dns" | "js" | "crawl" | "hidden" | "headless" => 2,
            "cloud" | "scm" => 3,
            _ => 2, // default to app-layer evaluation
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
        let (live_tx, mut live_rx) = mpsc::unbounded_channel::<Finding>();

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
        let mut global_seen = HashSet::new();
        global_seen.insert(target_streaming_key(&cascade_targets[0]));

        for phase_scanners in self.phases {
            if phase_scanners.is_empty() {
                continue;
            }

            // For each scanner in this phase, create boundaries
            let mut inboxes = Vec::new();
            let (target_tx, mut target_rx) = mpsc::unbounded_channel::<Target>();
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

                let (in_tx, in_rx) = mpsc::unbounded_channel::<Target>();
                inboxes.push((Arc::clone(&scanner), in_tx));

                let input = ScanInput {
                    seed: seed.to_string(),
                    target_rx: tokio::sync::Mutex::new(in_rx),
                    live_tx: live_tx.clone(),
                    target_tx: target_tx.clone(),
                    resolver: Arc::clone(&resolver),
                };

                let conf = config.clone();
                handles.push(tokio::spawn(async move {
                    if let Err(e) = scanner.run(input, &conf).await {
                        tracing::error!(scanner = scanner.name(), err = %e, "Scanner failed");
                    }
                }));
            }

            // Stream currently known targets into the matching phase inboxes
            for target in &cascade_targets {
                for (scanner, in_tx) in &inboxes {
                    if scanner.accepts(target) {
                        let _ = in_tx.send(target.clone());
                    }
                }
            }

            // Close all phase inboxes so the scanners naturally terminate when done.
            drop(inboxes);
            drop(target_tx); // Router copy dropped to break infinite wait.

            // Collect any NEW targets discovered by this phase.
            let mut new_in_phase = Vec::new();
            while let Some(t) = target_rx.recv().await {
                let key = target_streaming_key(&t);
                if global_seen.insert(key) {
                    new_in_phase.push(t);
                }
            }

            // Await phase completion
            for handle in handles {
                let _ = handle.await;
            }

            // Append new targets so the *next* phase evaluates the sum total
            cascade_targets.extend(new_in_phase);
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
