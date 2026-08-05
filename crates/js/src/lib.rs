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

/// Maximum bytes to read from an HTTP response body (HTML or JS) before truncating.
/// 4 MB is large enough for any realistic JS bundle while bounding memory
/// against infinite-chunked-transfer or compression-bomb attacks.
const MAX_JS_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Maximum Content-Length to accept for HTML pages.
/// Pages larger than this are almost certainly not real web apps (blob storage
/// directory listings, accidental dump endpoints); skip them.
const MAX_HTML_CONTENT_LENGTH: u64 = 5 * 1024 * 1024;

/// Maximum Content-Length to accept for individual JS files.
const MAX_JS_CONTENT_LENGTH: u64 = 10 * 1024 * 1024;

/// True when a JS asset Content-Length exceeds the download cap.
fn is_oversized_js_content_length(len: u64) -> bool {
    len > MAX_JS_CONTENT_LENGTH
}

use async_trait::async_trait;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use gossan_core::HostRateLimiter;
use gossan_core::{Config, ScanClient, ScanInput, Scanner, Target};
use secfinding::{Evidence, Finding, FindingBuilder, Severity};
use std::sync::Arc;
use tokio::sync::Semaphore;
/// JavaScript analysis scanner (secrets, endpoints, source maps, and WASM).
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
        let rate_limiter = Arc::new(HostRateLimiter::from_config(config));
        let semaphore = Arc::new(Semaphore::new(config.concurrency.max(1)));
        let mut rx = input.target_rx.lock().await;
        let mut workers = FuturesUnordered::new();

        // Stream targets as they arrive: spawn analysis under the concurrency
        // semaphore instead of buffering until the sender closes (which
        // deadlocks sibling scanners sharing this receiver mutex).
        loop {
            tokio::select! {
                opt_target = rx.recv() => {
                    match opt_target {
                        Some(target) => {
                            if !self.accepts(&target) {
                                continue;
                            }
                            let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
                                break;
                            };
                            let client = client.clone();
                            let target_tx = input.target_tx.clone();
                            let rl = Arc::clone(&rate_limiter);
                            let live_tx = input.live_tx.clone();
                            workers.push(tokio::spawn(async move {
                                let _permit = permit;
                                match analyze(&client, &target, &target_tx, &rl).await {
                                    Ok(batch) => {
                                        for f in batch {
                                            if let Err(e) = live_tx.send(f).await {
                                                tracing::warn!(error = %e, "js: failed to emit finding");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            target = ?target,
                                            error = %e,
                                            "js analyze failed for target"
                                        );
                                    }
                                }
                            }));
                        }
                        None => break,
                    }
                }
                Some(res) = workers.next(), if !workers.is_empty() => {
                    if let Err(e) = res {
                        tracing::error!(error = %e, "js worker join failed");
                    }
                }
            }
        }

        while let Some(res) = workers.next().await {
            if let Err(e) = res {
                tracing::error!(error = %e, "js worker join failed");
            }
        }
        Ok(())
    }
}

async fn analyze(
    client: &reqwest::Client,
    target: &Target,
    target_tx: &tokio::sync::mpsc::Sender<Target>,
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
        if len > MAX_HTML_CONTENT_LENGTH {
            tracing::warn!(url = %asset.url, size = len, "skipping massive HTML file");
            return Ok(vec![]);
        }
    }

    let html = gossan_core::net::bounded_text(resp, MAX_JS_RESPONSE_BYTES).await?;
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

                let resp = match client.get(&url).send().await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(error = %e, %url, "js asset fetch failed");
                        return None;
                    }
                };

                // Require success status
                if !resp.status().is_success() {
                    tracing::debug!(status = %resp.status(), %url, "js asset non-success status");
                    return None;
                }

                // Protection: don't download huge JS files (max 10MB)
                if let Some(len) = resp.content_length() {
                    if is_oversized_js_content_length(len) {
                        tracing::warn!(
                            url = %url,
                            size = len,
                            limit = MAX_JS_CONTENT_LENGTH,
                            "skipping oversized JS asset"
                        );
                        return None;
                    }
                }

                let body = match gossan_core::net::bounded_text(resp, MAX_JS_RESPONSE_BYTES).await {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(url = %url, error = %e, "js asset body read failed");
                        return None;
                    }
                };
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

            // Only pivot onto hosts inside the seed target's registrable
            // scope — third-party CDNs/APIs stay as findings, not scan targets.
            let seed_host = asset.url.host_str().unwrap_or("");
            if let Some(new_target) = ep.as_target_in_scope(seed_host) {
                if let Err(e) = target_tx.send(new_target).await {
                    tracing::warn!(error = %e, "js: failed to emit in-scope endpoint target");
                }
            }
        }

        // Inline secret detection on raw JS content
        findings.extend(secrets::scan(js_url, body, target));

        // Source map detection, look for //# sourceMappingURL= comment
        if let Some(map_url) = extract_sourcemap_url(js_url, body, &asset.url) {
            sourcemap_urls.push(map_url);
        }
    }

    // Fully extract source maps, decompress sourcesContent, scan ALL files for secrets
    let map_findings: Vec<Vec<Finding>> = futures::stream::iter(sourcemap_urls)
        .map(|map_url| {
            let client = client.clone();
            let target = target.clone();
            let rl = rate_limiter;
            async move { probe_sourcemap_full(&client, &map_url, &target, rl).await }
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

    // Oneshot: Verify discovered secrets actively
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
    let mut map_path = line.split("sourceMappingURL=").nth(1)?.trim();
    // Strip trailing block-comment closer when the directive sits inside /* ... */
    if let Some(stripped) = map_path.strip_suffix("*/") {
        map_path = stripped.trim_end();
    }
    // Also cut at whitespace / quotes that sometimes trail the URL token.
    if let Some(end) = map_path.find(|c: char| c.is_whitespace() || c == '"' || c == '\'') {
        map_path = map_path[..end].trim_end();
    }

    // Reject empty or whitespace-only map paths
    if map_path.is_empty() {
        return None;
    }

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

/// Fully extract source maps (decompress sourcesContent, scan ALL original files for secrets).
/// Returns ALL findings: one header finding + per-file secret findings.
pub(crate) async fn probe_sourcemap_full(
    client: &reqwest::Client,
    map_url: &str,
    target: &Target,
    rate_limiter: &HostRateLimiter,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Ok(parsed) = url::Url::parse(map_url) {
        let host = parsed.host_str().unwrap_or("");
        rate_limiter.until_ready(host).await;
    }

    let Ok(resp) = client.get(map_url).send().await else {
        return findings;
    };
    let status = resp.status().as_u16();
    if status != 200 {
        return findings;
    }
    let Ok(body) = gossan_core::net::bounded_text(resp, MAX_JS_RESPONSE_BYTES).await else {
        return findings;
    };
    if !body.contains("\"sources\"") {
        return findings;
    }

    let map = match serde_json::from_str::<serde_json::Value>(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                map_url,
                error = %e,
                "js: source map JSON parse failed; skipping sourcesContent scan"
            );
            return findings;
        }
    };

    let sources: Vec<String> = match map.get("sources") {
        Some(v) => match v.as_array() {
            Some(arr) => arr
                .iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect(),
            None => {
                tracing::warn!(
                    map_url,
                    "js: source map 'sources' is not an array; treating as empty"
                );
                Vec::new()
            }
        },
        None => Vec::new(),
    };

    let contents: Vec<Option<String>> = match map.get("sourcesContent") {
        Some(v) => match v.as_array() {
            Some(arr) => arr.iter().map(|x| x.as_str().map(String::from)).collect(),
            None => {
                tracing::warn!(
                    map_url,
                    "js: source map 'sourcesContent' is not an array; treating as empty"
                );
                Vec::new()
            }
        },
        None => Vec::new(),
    };

    let file_count = sources.len();
    let has_content = !contents.is_empty();

    // Header finding
    gossan_core::try_push_finding(
        finding_builder(target,
            if has_content { Severity::High } else { Severity::Medium },
            format!("JS source map: {} original files exposed", file_count),
            format!("Source map at {}: {} original source files{}. Attacker can recover full dev codebase.",
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

    // Scan each sourcesContent entry for secrets, this is the full original source code
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_sourcemap_url_finds_comment() {
        let body = "console.log(1);\n//# sourceMappingURL=app.js.map\n";
        let base = url::Url::parse("https://example.com/").unwrap();
        let got = extract_sourcemap_url("https://example.com/app.js", body, &base);
        assert_eq!(got, Some("https://example.com/app.js.map".to_string()));
    }

    #[test]
    fn extract_sourcemap_url_skips_data_uri() {
        let body = "//# sourceMappingURL=data:application/json;base64,abc123\n";
        let base = url::Url::parse("https://example.com/").unwrap();
        let got = extract_sourcemap_url("https://example.com/app.js", body, &base);
        assert_eq!(got, None);
    }

    #[test]
    fn extract_sourcemap_url_skips_inline_comment() {
        let body = "var x = 1; //# sourceMappingURL=app.js.map";
        let base = url::Url::parse("https://example.com/").unwrap();
        let got = extract_sourcemap_url("https://example.com/app.js", body, &base);
        assert_eq!(got, Some("https://example.com/app.js.map".to_string()));
    }

    #[test]
    fn extract_sourcemap_url_malformed_last_line() {
        let body = "//# sourceMappingURL=";
        let base = url::Url::parse("https://example.com/").unwrap();
        let got = extract_sourcemap_url("https://example.com/app.js", body, &base);
        assert_eq!(got, None);
    }

    #[test]
    fn extract_script_urls_finds_script_tags() {
        let html = r#"
            <html>
            <script src="/app.js"></script>
            <script src="https://cdn.example.com/lib.js"></script>
            <script>inline</script>
            </html>
        "#;
        let base = url::Url::parse("https://example.com/").unwrap();
        let urls = extract_script_urls(html, &base);
        assert!(urls.contains(&"https://example.com/app.js".to_string()));
        assert!(urls.contains(&"https://cdn.example.com/lib.js".to_string()));
        assert_eq!(urls.len(), 2);
    }

    #[test]
    fn extract_script_urls_filters_non_http() {
        let html = r#"<script src="javascript:alert(1)"></script>"#;
        let base = url::Url::parse("https://example.com/").unwrap();
        let urls = extract_script_urls(html, &base);
        assert!(urls.is_empty());
    }

    #[test]
    fn extract_script_urls_empty_html() {
        let base = url::Url::parse("https://example.com/").unwrap();
        assert!(extract_script_urls("", &base).is_empty());
    }

    #[test]
    fn extract_script_urls_rejects_malformed_base() {
        // base.join may fail for invalid relative URLs, but should not panic.
        let html = r#"<script src="http://[::1"></script>"#;
        let base = url::Url::parse("https://example.com/").unwrap();
        let urls = extract_script_urls(html, &base);
        assert!(urls.is_empty());
    }


    #[test]
    fn oversized_js_content_length_boundary() {
        // Adversarial: exact limit must still download; one byte over must skip+warn path.
        assert!(!is_oversized_js_content_length(MAX_JS_CONTENT_LENGTH));
        assert!(is_oversized_js_content_length(MAX_JS_CONTENT_LENGTH + 1));
        assert!(!is_oversized_js_content_length(0));
    }

    // ── proptest property tests ───────────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn extract_sourcemap_url_never_panics(body in "\\PC{0,4096}") {
            let base = url::Url::parse("https://example.com/").unwrap();
            let _ = extract_sourcemap_url("https://example.com/app.js", &body, &base);
        }

        #[test]
        fn extract_script_urls_never_panics(html in "\\PC{0,4096}") {
            let base = url::Url::parse("https://example.com/").unwrap();
            let _ = extract_script_urls(&html, &base);
        }

        #[test]
        fn extract_script_urls_returns_https_only(html in "\\PC{0,4096}") {
            let base = url::Url::parse("https://example.com/").unwrap();
            for url in extract_script_urls(&html, &base) {
                prop_assert!(
                    url.starts_with("http://") || url.starts_with("https://"),
                    "non-HTTP URL leaked through: {}",
                    url
                );
            }
        }
    }
}
