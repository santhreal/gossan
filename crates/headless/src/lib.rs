use async_trait::async_trait;
use chromiumoxide::{Browser, BrowserConfig};
use futures::StreamExt;
use gossan_core::{Config, ScanInput, ScanOutput, Scanner, Target};
use secfinding::{Evidence, Finding, FindingBuilder, Severity};
use std::time::Duration;

pub struct HeadlessScanner;

fn finding_builder(
    target: &Target,
    severity: Severity,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> FindingBuilder {
    Finding::builder("headless", target.domain().unwrap_or("?"), severity)
        .title(title)
        .detail(detail)
}

#[async_trait]
impl Scanner for HeadlessScanner {
    fn name(&self) -> &'static str {
        "headless"
    }
    fn tags(&self) -> &[&'static str] {
        &["active", "web", "rendering"]
    }
    fn accepts(&self, target: &Target) -> bool {
        matches!(target, Target::Web(_))
    }

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<ScanOutput> {
        let mut out = ScanOutput::empty();

        let owned: Vec<Target> = input
            .targets
            .into_iter()
            .filter(|t| self.accepts(t))
            .collect();

        // Launch the chromium browser natively
        // Requires chromium/chrome to be installed on the host system.
        let (browser, mut handler) = Browser::launch(
            BrowserConfig::builder()
                .disable_default_args() // Reduces fingerprinting footprint
                .request_timeout(config.timeout())
                .build()
                .map_err(|e| anyhow::anyhow!("Failed to build browser config: {:?}", e))?,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to launch browser: {:?}", e))?;

        let browser = std::sync::Arc::new(browser);

        // Maintain the handler connection
        let handle = tokio::spawn(async move {
            while let Some(h) = handler.next().await {
                if h.is_err() {
                    break;
                }
            }
        });

        // Parallel execution of all targets using the single browser instance
        let findings: Vec<Vec<Finding>> = futures::stream::iter(owned)
            .map(|target| {
                let browser = std::sync::Arc::clone(&browser);
                async move { analyze_target(&browser, target).await.unwrap_or_default() }
            })
            // Browser limit for tabs
            .buffer_unordered(config.concurrency.min(10))
            .collect()
            .await;

        for batch in findings {
            out.findings.extend(batch);
        }

        handle.abort();

        Ok(out)
    }
}

async fn analyze_target(browser: &Browser, target: Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = &target else {
        return Ok(vec![]);
    };
    let mut findings = Vec::new();

    let page = browser.new_page(asset.url.as_str()).await?;

    // Wait for the DOM to settle and XHRs to fire
    page.wait_for_navigation().await.ok();

    let mut request_events = page
        .event_listener::<chromiumoxide::cdp::browser_protocol::network::EventRequestWillBeSent>()
        .await?;

    // We let the page idle slightly to allow asynchronous API fetch calls (React/Vue/Angular)
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Drain all trapped network requests
    while let Ok(Some(req)) =
        tokio::time::timeout(Duration::from_millis(500), request_events.next()).await
    {
        let url = req.request.url.clone();

        // Filter out obvious noise, trap API paths
        if url.contains("api") || url.ends_with(".json") || url.ends_with(".graphql") {
            findings.push(
                finding_builder(
                    &target,
                    Severity::Info,
                    "Dynamic API Endpoint Trapped",
                    format!("Trapped runtime XHR request to: {}", url),
                )
                .tag("recon")
                .tag("dynamic_xhr")
                .evidence(Evidence::HttpResponse {
                    status: 200,
                    headers: vec![],
                    body_excerpt: Some(format!(
                        "Method: {}, Headers: {:?}",
                        req.request.method, req.request.headers
                    )),
                })
                .build()
                .expect("finding builder: required fields are set"),
            );
        }
    }

    page.close().await.ok();
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::{HostTarget, Protocol, Scanner, ServiceTarget, Target, WebAssetTarget};
    use url::Url;

    fn web_target() -> Target {
        Target::Web(Box::new(WebAssetTarget {
            url: Url::parse("https://example.com").unwrap(),
            service: ServiceTarget {
                host: HostTarget {
                    ip: "127.0.0.1".parse().unwrap(),
                    domain: Some("example.com".into()),
                },
                port: 443,
                protocol: Protocol::Tcp,
                banner: None,
                tls: true,
            },
            tech: vec![],
            status: 200,
            title: None,
            favicon_hash: None,
            body_hash: None,
            forms: vec![],
            params: vec![],
        }))
    }

    #[test]
    fn scanner_metadata_is_stable() {
        let scanner = HeadlessScanner;
        assert_eq!(scanner.name(), "headless");
        assert_eq!(scanner.tags(), &["active", "web", "rendering"]);
    }

    #[test]
    fn scanner_accepts_only_web_targets() {
        let scanner = HeadlessScanner;
        assert!(scanner.accepts(&web_target()));
        assert!(!scanner.accepts(&Target::Host(HostTarget {
            ip: "127.0.0.1".parse().unwrap(),
            domain: None,
        })));
    }
}
