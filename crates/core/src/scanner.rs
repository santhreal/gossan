//! The [`Scanner`] trait — every gossan module implements this.
//!
//! Defines `run()`, `accepts()`, and metadata (`name`, `tags`) that the
//! pipeline uses to compose scanner stages.

use async_trait::async_trait;
use hickory_resolver::TokioAsyncResolver;
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::{Config, Finding, Target};

/// Input to a scanner stage — seed, targets, and live streaming channels.
/// ALL operations must be stream-oriented. No memory buffering.
pub struct ScanInput {
    /// Original seed supplied by the scan request.
    pub seed: String,
    /// Inbound stream of targets for this scanner stage.
    pub target_rx: tokio::sync::Mutex<UnboundedReceiver<Target>>,
    /// Live finding stream shared by the pipeline.
    pub live_tx: UnboundedSender<Finding>,
    /// Downstream target stream for newly discovered assets.
    pub target_tx: UnboundedSender<Target>,
    /// Shared DNS resolver configured for this scan.
    pub resolver: Arc<TokioAsyncResolver>,
}

impl ScanInput {
    /// Emit a finding to the live channel.
    pub fn emit(&self, f: Finding) {
        let _ = self.live_tx.send(f);
    }

    /// Emit a discovered target downstream.
    pub fn emit_target(&self, t: Target) {
        let _ = self.target_tx.send(t);
    }
}

/// Every scanner module implements this trait and nothing else.
#[async_trait]
pub trait Scanner: Send + Sync {
    /// Stable scanner name used in logs, configuration, and output metadata.
    fn name(&self) -> &'static str;
    /// Scanner capability tags used for module selection and reporting.
    fn tags(&self) -> &[&'static str];
    /// Return true when this scanner can process the supplied target.
    fn accepts(&self, target: &Target) -> bool;

    /// Execute the scan as a pure streaming node in the DAG.
    /// Findings and Targets MUST be emitted via `input.emit()` and `input.emit_target()`.
    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<()>;
}
