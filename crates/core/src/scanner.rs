use async_trait::async_trait;
use tokio::sync::mpsc::UnboundedSender;

use crate::{Config, Finding, Target};

/// Input to a scanner stage — seed, targets, and optional live streaming channels.
pub struct ScanInput {
    /// The original user-supplied seed (domain, org name, CIDR, URL).
    pub seed: String,
    /// Targets fed from upstream scanners, or the seed parsed into a target for the first stage.
    pub targets: Vec<Target>,
    /// If set, scanners emit findings here in real-time (before returning ScanOutput).
    /// Enables live progress output in the CLI without changing the Scanner trait API.
    pub live_tx: Option<UnboundedSender<Finding>>,
    /// If set, scanners emit discovered targets here in real-time.
    /// Enables the streaming pipeline: downstream stages start processing
    /// as soon as the first targets arrive, without waiting for this stage to finish.
    pub target_tx: Option<UnboundedSender<Target>>,
}

impl ScanInput {
    /// Emit a finding to the live channel if connected. Fire-and-forget.
    pub fn emit(&self, f: Finding) {
        if let Some(tx) = &self.live_tx {
            let _ = tx.send(f);
        }
    }

    /// Emit a discovered target to the streaming pipeline channel if connected.
    /// Scanners should call this for every confirmed target as soon as it is resolved.
    pub fn emit_target(&self, t: Target) {
        if let Some(tx) = &self.target_tx {
            let _ = tx.send(t);
        }
    }
}

/// Output from a scanner stage — discovered findings and downstream targets.
pub struct ScanOutput {
    /// Security findings from this scanner.
    pub findings: Vec<Finding>,
    /// New targets discovered — passed downstream to subsequent scanners.
    pub targets: Vec<Target>,
}

impl ScanOutput {
    /// Create an empty output with no findings and no targets.
    pub fn empty() -> Self {
        Self {
            findings: Vec::new(),
            targets: Vec::new(),
        }
    }
}

/// Every scanner module implements this trait and nothing else.
///
/// Architecture rules:
/// - `gossan-core` knows nothing about individual scanners.
/// - Each scanner crate depends only on `gossan-core`.
/// - `gossan` (CLI crate) depends on all scanner crates and wires the pipeline.
/// - Object-safe via `async_trait` so scanners live in `Vec<Box<dyn Scanner>>`.
#[async_trait]
pub trait Scanner: Send + Sync {
    /// Short identifier shown in CLI output and stored in Finding.scanner.
    fn name(&self) -> &'static str;

    /// Labels used for `--only` / `--skip` filtering in the CLI.
    fn tags(&self) -> &[&'static str];

    /// Return true if this scanner can process the given target type.
    /// The pipeline uses this to route targets — scanners only see what they accept.
    fn accepts(&self, target: &Target) -> bool;

    /// Execute the scan. Must not panic — use anyhow::Result for all errors.
    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<ScanOutput>;
}
