//! Panoram tech stack scanner — thin integration layer.
//!
//! All fingerprinting, security header auditing, and favicon hashing logic
//! lives in the standalone [`truestack`] crate. This module adapts
//! `truestack` results into the panoram scanner pipeline.

extern crate self as reqwest;
pub use stealthreq::http::{Client, Method, Proxy, Request, Response, StatusCode, Url};
pub use stealthreq::http::{header, redirect};

mod bridge;

use async_trait::async_trait;
use futures::StreamExt;
use gossan_core::{
    build_client, Config, ScanInput, ScanOutput, Scanner, ServiceTarget, Target, WebAssetTarget,
};
use secfinding::Finding;

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

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<ScanOutput> {
        let mut out = ScanOutput::empty();
        let client = build_client(config, true)?;

        let web_targets: Vec<ServiceTarget> = input
            .targets
            .into_iter()
            .filter_map(|t| {
                if let Target::Service(s) = t {
                    Some(s)
                } else {
                    None
                }
            })
            .filter(|s| s.is_web())
            .collect();

        let results: Vec<Option<(WebAssetTarget, Vec<Finding>)>> =
            futures::stream::iter(web_targets)
                .map(|svc| {
                    let client = client.clone();
                    async move { bridge::probe(&client, svc).await.ok() }
                })
                .buffer_unordered(config.concurrency)
                .collect()
                .await;

        for item in results.into_iter().flatten() {
            let (asset, header_findings) = item;
            tracing::debug!(
                url = %asset.url,
                tech = ?asset.tech.iter().map(|t| &t.name).collect::<Vec<_>>(),
                "web asset"
            );
            out.findings.extend(header_findings);
            out.targets.push(Target::Web(Box::new(asset)));
        }

        Ok(out)
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
