#![forbid(unsafe_code)]
// pedantic moved to workspace [lints.clippy] in root Cargo.toml
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]

//! Panoram tech stack scanner (thin integration layer).
//!
//! All fingerprinting, security header auditing, and favicon hashing logic
//! lives in the standalone [`truestack`] crate. This module adapts
//! `truestack` results into the panoram scanner pipeline.

pub mod bridge;

/// Maximum bytes to read from an HTTP response body for tech-stack fingerprinting.
/// 2 MiB is large enough for any realistic HTML page while keeping memory bounded.
pub(crate) const MAX_TECHSTACK_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Maximum bytes to read from a favicon response.
/// Favicons are typically <100 KB; 5 MiB is a generous ceiling.
pub(crate) const MAX_TECHSTACK_FAVICON_BYTES: usize = 5 * 1024 * 1024;

use async_trait::async_trait;
use futures::StreamExt;
use gossan_core::{Config, ScanClient, ScanInput, Scanner, ServiceTarget, Target, WebAssetTarget};
use secfinding::Finding;
use std::sync::Arc;
/// Technology fingerprinting scanner: HTTP headers, HTML patterns, and JS frameworks.
pub struct TechStackScanner;

#[async_trait]
impl Scanner for TechStackScanner {
    fn name(&self) -> &'static str {
        "techstack"
    }
    fn tags(&self) -> &[&'static str] {
        &["active", "web", "fingerprint"]
    }
    fn accepts(&self, target: &Target) -> bool {
        matches!(target, Target::Service(s) if s.is_web())
    }

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<()> {
        let client = ScanClient::from_config(config, Arc::clone(&input.resolver))?;

        // Drain the streaming target receiver. Techstack fingerprinting is
        // batch-shaped (per-asset HTTP probes via `buffer_unordered`), so
        // the receiver is fully drained up front rather than processed
        // incrementally.
        let web_targets: Vec<ServiceTarget> = {
            let mut rx = input.target_rx.lock().await;
            let mut buf = Vec::new();
            // recv() until the pipeline closes the inbox — try_recv races the
            // sender and drops asynchronously delivered targets.
            while let Some(t) = rx.recv().await {
                if let Target::Service(s) = t {
                    if s.is_web() {
                        buf.push(s);
                    }
                }
            }
            buf
        };

        let results: Vec<Result<(WebAssetTarget, Vec<Finding>), anyhow::Error>> =
            futures::stream::iter(web_targets)
                .map(|svc| {
                    let client = client.clone();
                    async move { bridge::probe(&client, svc).await }
                })
                .buffer_unordered(config.concurrency.max(1))
                .collect()
                .await;

        for item in results {
            let (asset, header_findings) = match item {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "techstack probe failed");
                    continue;
                }
            };
            tracing::debug!(
                url = %asset.url,
                tech = ?asset.tech.iter().map(|t| &t.name).collect::<Vec<_>>(),
                "web asset"
            );
            for f in header_findings {
                input.emit(f).await;
            }
            input.emit_target(Target::Web(Box::new(asset))).await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::{HostTarget, Protocol, Scanner};

    fn service(port: u16, banner: Option<&str>) -> Target {
        Target::Service(ServiceTarget {
            host: HostTarget {
                ip: "127.0.0.1".parse().unwrap(),
                domain: Some("example.com".into()),
            },
            port,
            protocol: Protocol::Tcp,
            banner: banner.map(str::to_string),
            tls: port == 443,
        })
    }

    #[test]
    fn scanner_accepts_only_web_services() {
        let scanner = TechStackScanner;
        assert!(scanner.accepts(&service(443, None)));
        assert!(scanner.accepts(&service(1234, Some("HTTP/1.1 200 OK"))));
        assert!(!scanner.accepts(&service(22, Some("SSH-2.0"))));
    }

    #[test]
    fn scanner_metadata_is_stable() {
        let scanner = TechStackScanner;
        assert_eq!(scanner.name(), "techstack");
        assert_eq!(scanner.tags(), &["active", "web", "fingerprint"]);
    }
}
