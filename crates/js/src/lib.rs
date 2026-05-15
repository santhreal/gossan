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

//! JavaScript analysis scanner.
//! Finds `<script src>` URLs, fetches each JS file, extracts endpoints,
//! detects hardcoded secrets, and probes for source maps.

pub mod endpoints;
pub mod secrets;
pub mod verifiers;

mod wasm;

use async_trait::async_trait;
use futures::StreamExt;
use gossan_core::HostRateLimiter;
use gossan_core::{Config, ScanClient, ScanInput, Scanner, Target};
use secfinding::{Evidence, Finding, FindingBuilder, Severity};
use std::sync::Arc;
/// JavaScript analysis scanner — secrets, endpoints, source maps, and WASM.
pub struct JsScanner;

pub(crate) fn finding_builder(
    target: &Target,
    severity: Severity,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> FindingBuilder {
    Finding::builder("js", target.domain().unwrap_or("?"), severity)
        .title(title)
        .detail(detail)
        .kind(secfinding::FindingKind::Exposure)
}

#[async_trait]
impl Scanner for JsScanner {
    fn name(&self) -> &'static str {
        "js"
    }
    fn tags(&self) -> &[&'static str] {
        &["active", "web", "js"]
    }
    fn accepts(&self, target: &Target) -> bool {
        matches!(target, Target::Web(_))
    }

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<()> {
        let client = ScanClient::from_config(config, Arc::clone(&input.resolver))?;

        // Drain the inbound channel — the pre-streaming `targets:
        // Vec<Target>` field is gone; targets arrive via `target_rx`.
        let mut owned: Vec<Target> = Vec::new();
        {
            let mut rx = input.target_rx.lock().await;
            while let Some(t) = rx.recv().await {
                if self.accepts(&t) {
                    owned.push(t);
                }
            }
        }

        let rate_limiter = Arc::new(HostRateLimiter::new(config.rate_limit));

        let findings: Vec<Vec<Finding>> = futures::stream::iter(owned)
            .map(|target| {
                let client = client.clone();
                let target_tx = input.target_tx.clone();
                let rl = Arc::clone(&rate_limiter);
                async move {
                    match analyze(&client, &target, &target_tx, &rl).await {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::error!(target = ?target, error = %e, "js analyze failed for target");
                            Vec::new()
                        }
                    }
                }
            })
            .buffer_unordered(config.concurrency)
            .collect()
            .await;

        for batch in findings {
            for f in batch {
                input.emit(f);
            }
        }
        Ok(())
    }
}

async fn analyze(
    client: &reqwest::Client,
    target: &Target,
    target_tx: &tokio::sync::mpsc::UnboundedSender<Target>,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let mut findings = Vec::new();

    // ── Safe HTML Fetch ──────────────────────────────────────────────────
    let host = asset.url.host_str().unwrap_or("");
    rate_limiter.until_ready(host).await;

    let resp = client.get(asset.url.as_str()).send().await?;

    // Ensure we got a successful status code
    if !resp.status().is_success() {
        tracing::warn!(url = %asset.url, status = %resp.status(), "non-success status fetching HTML");
        return Ok(vec![]);
    }

    // Protection: don't download huge HTML files (max 5MB)
    if let Some(len) = resp.content_length() {
        if len > 5 * 1024 * 1024 {
            tracing::warn!(url = %asset.url, size = len, "skipping massive HTML file");
            return Ok(vec![]);
        }
    }

    let html = gossan_core::net::bounded_text(resp, 4 * 1024 * 1024).await?;
    let js_urls = extract_script_urls(&html, &asset.url);

    // ... (wasm task remains same)
    let wasm_task = {
        let client = client.clone();
        let html = html.clone();
        let base = asset.url.clone();
        let target = target.clone();
        tokio::spawn(async move { wasm::probe(&client, &html, &base, &target).await })
    };

    tracing::debug!(url = %asset.url, scripts = js_urls.len(), "js analysis");

    // Fetch all JS files concurrently with strict size limits
    let js_bodies: Vec<(String, String)> = futures::stream::iter(js_urls)
        .map(|url| {
            let client = client.clone();
            let rl = rate_limiter;
            async move {
                let parsed_url = url::Url::parse(&url).ok()?;
                let host = parsed_url.host_str().unwrap_or("");
                rl.until_ready(host).await;

                let resp = client.get(&url).send().await.ok()?;

                // Require success status
                if !resp.status().is_success() {
                    return None;
                }

                // Protection: don't download huge JS files (max 10MB)
                if let Some(len) = resp.content_length() {
                    if len > 10 * 1024 * 1024 {
                        return None;
                    }
                }

                let body = gossan_core::net::bounded_text(resp, 4 * 1024 * 1024)
                    .await
                    .ok()?;
                Some((url, body))
            }
        })
        .buffer_unordered(20)
        .filter_map(|x| async move { x })
        .collect()
        .await;

    // Source map URLs to probe (collected across all JS files)
    let mut sourcemap_urls: Vec<String> = Vec::new();

    for (js_url, body) in &js_bodies {
        // Endpoint extraction
        for ep in endpoints::extract(js_url, body) {
            gossan_core::try_push_finding(ep.into_finding(target), &mut findings);

            // Emit new targets if they are external domains or IPs
            if let Some(new_target) = ep.as_target() {
                let _ = target_tx.send(new_target);
            }
        }

        // Inline secret detection on raw JS content
        findings.extend(secrets::scan(js_url, body, target));

        // Source map detection — look for //# sourceMappingURL= comment
        if let Some(map_url) = extract_sourcemap_url(js_url, body, &asset.url) {
            sourcemap_urls.push(map_url);
        }
    }

    // Fully extract source maps — decompress sourcesContent, scan ALL files for secrets
    let map_findings: Vec<Vec<Finding>> = futures::stream::iter(sourcemap_urls)
        .map(|map_url| {
            let client = client.clone();
            let target = target.clone();
            async move { probe_sourcemap_full(&client, &map_url, &target).await }
        })
        .buffer_unordered(10)
        .collect()
        .await;

    for batch in map_findings {
        findings.extend(batch);
    }

    // Collect WASM results
    if let Ok(wasm_findings) = wasm_task.await {
        findings.extend(wasm_findings);
    }

    // Legendary: Verify discovered secrets actively
    let verifier = verifiers::VerifierEngine::new();
    verifier.verify_all(&mut findings).await;

    Ok(findings)
}

/// Extract the sourceMappingURL from the last line of a JS file.
fn extract_sourcemap_url(js_url: &str, body: &str, base: &url::Url) -> Option<String> {
    // Look for //# sourceMappingURL= or //@ sourceMappingURL=
    let line = body
        .lines()
        .rev()
        .take(5)
        .find(|l| l.contains("sourceMappingURL="))?;
    let map_path = line.split("sourceMappingURL=").nth(1)?.trim();

    // Skip inline data URIs
    if map_path.starts_with("data:") {
        return None;
    }

    // Resolve relative to JS file URL
    let js_base = url::Url::parse(js_url).ok()?;
    let resolved = js_base
        .join(map_path)
        .or_else(|_| base.join(map_path))
        .ok()?;
    Some(resolved.to_string())
}

/// Fully extract source maps — decompress sourcesContent, scan ALL original files for secrets.
/// Returns ALL findings: one header finding + per-file secret findings.
pub(crate) async fn probe_sourcemap_full(
    client: &reqwest::Client,
    map_url: &str,
    target: &Target,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let Ok(resp) = client.get(map_url).send().await else {
        return findings;
    };
    let status = resp.status().as_u16();
    if status != 200 {
        return findings;
    }
    let Ok(body) = gossan_core::net::bounded_text(resp, 4 * 1024 * 1024).await else {
        return findings;
    };
    if !body.contains("\"sources\"") {
        return findings;
    }

    let Ok(map) = serde_json::from_str::<serde_json::Value>(&body) else {
        return findings;
    };

    let sources: Vec<String> = map
        .get("sources")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let contents: Vec<Option<String>> = map
        .get("sourcesContent")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let file_count = sources.len();
    let has_content = !contents.is_empty();

    // Header finding
    gossan_core::try_push_finding(
        finding_builder(target,
            if has_content { Severity::High } else { Severity::Medium },
            format!("JS source map: {} original files exposed", file_count),
            format!("Source map at {} — {} original source files{}. Attacker can recover full dev codebase.",
                map_url, file_count,
                if has_content { " with sourcesContent (full code)" } else { " (paths only)" }))
        .evidence(Evidence::HttpResponse {
            status,
            headers: vec![],
            body_excerpt: Some(std::sync::Arc::from(
                sources.iter().take(10).cloned().collect::<Vec<_>>().join("\n").as_str(),
            )),
        })
        .tag("source-map").tag("js"),
        &mut findings,
    );

    // Scan each sourcesContent entry for secrets — this is the full original source code
    for (i, content) in contents.iter().enumerate() {
        if let Some(code) = content {
            let source_name = sources
                .get(i)
                .cloned()
                .unwrap_or_else(|| format!("source_{i}"));
            let source_label = format!("{map_url}!{source_name}");
            findings.extend(secrets::scan(&source_label, code, target));
        }
    }

    findings
}

fn extract_script_urls(html: &str, base: &url::Url) -> Vec<String> {
    let doc = scraper::Html::parse_document(html);
    let Ok(sel) = scraper::Selector::parse("script[src]") else {
        return vec![];
    };

    doc.select(&sel)
        .filter_map(|el| el.value().attr("src"))
        .filter_map(|src| base.join(src).ok())
        .filter(|u: &url::Url| u.scheme() == "http" || u.scheme() == "https")
        .map(|u| u.to_string())
        .collect()
}
