//! JavaScript analysis scanner.
//! Finds <script src> URLs, fetches each JS file, extracts endpoints,
//! detects hardcoded secrets, and probes for source maps.

extern crate self as reqwest;
pub use upstream_reqwest::{header, redirect, Client, Method, Proxy, Request, Response, StatusCode, Url};

mod endpoints;
mod secrets;
mod wasm;

use async_trait::async_trait;
use futures::StreamExt;
use gossan_core::{build_client, Config, ScanInput, ScanOutput, Scanner, Target};
use secfinding::{Evidence, Finding, FindingBuilder, Severity};

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

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<ScanOutput> {
        let mut out = ScanOutput::empty();

        let client = build_client(config, true)?;

        let owned: Vec<Target> = input
            .targets
            .into_iter()
            .filter(|t| self.accepts(t))
            .collect();

        let findings: Vec<Vec<Finding>> = futures::stream::iter(owned)
            .map(|target| {
                let client = client.clone();
                async move { analyze(&client, &target).await.unwrap_or_default() }
            })
            .buffer_unordered(config.concurrency)
            .collect()
            .await;

        for batch in findings {
            out.findings.extend(batch);
        }
        Ok(out)
    }
}

async fn analyze(client: &reqwest::Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let mut findings = Vec::new();

    let html = client.get(asset.url.as_str()).send().await?.text().await?;
    let js_urls = extract_script_urls(&html, &asset.url);

    // WASM binary secrets scan (runs concurrently with JS analysis below)
    let wasm_task = {
        let client = client.clone();
        let html = html.clone();
        let base = asset.url.clone();
        let target = target.clone();
        tokio::spawn(async move { wasm::probe(&client, &html, &base, &target).await })
    };

    tracing::debug!(url = %asset.url, scripts = js_urls.len(), "js analysis");

    // Fetch all JS files concurrently
    let js_bodies: Vec<(String, String)> = futures::stream::iter(js_urls)
        .map(|url| {
            let client = client.clone();
            async move {
                let body = client.get(&url).send().await.ok()?.text().await.ok()?;
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
            findings.push(ep.into_finding(target.clone()));
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
    let Ok(body) = resp.text().await else {
        return findings;
    };
    if !body.contains("\"sources\"") {
        return findings;
    }

    let Ok(map) = serde_json::from_str::<serde_json::Value>(&body) else {
        return findings;
    };

    let sources: Vec<String> = map["sources"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let contents: Vec<Option<String>> = map["sourcesContent"]
        .as_array()
        .map(|arr| arr.iter().map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let file_count = sources.len();
    let has_content = !contents.is_empty();

    // Header finding
    findings.push(
        finding_builder(target,
            if has_content { Severity::High } else { Severity::Medium },
            format!("JS source map: {} original files exposed", file_count),
            format!("Source map at {} — {} original source files{}. Attacker can recover full dev codebase.",
                map_url, file_count,
                if has_content { " with sourcesContent (full code)" } else { " (paths only)" }))
        .evidence(Evidence::HttpResponse {
            status,
            headers: vec![],
            body_excerpt: Some(sources.iter().take(10).cloned().collect::<Vec<_>>().join("\n")),
        })
        .tag("source-map").tag("js")
        .build().expect("finding builder: required fields are set")
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

#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::{HostTarget, Protocol, Scanner, ServiceTarget, Target, WebAssetTarget};

    fn web_target() -> Target {
        Target::Web(Box::new(WebAssetTarget {
            url: url::Url::parse("https://example.com").unwrap(),
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
    fn scanner_accepts_only_web_targets() {
        let scanner = JsScanner;
        assert!(scanner.accepts(&web_target()));
        assert!(!scanner.accepts(&Target::Host(HostTarget {
            ip: "127.0.0.1".parse().unwrap(),
            domain: None,
        })));
    }

    #[test]
    fn extract_script_urls_resolves_relative_and_absolute_scripts() {
        let html = r#"<script src="/app.js"></script><script src="https://cdn.example.com/lib.js"></script>"#;
        let urls = extract_script_urls(html, &url::Url::parse("https://example.com").unwrap());
        assert!(urls.contains(&"https://example.com/app.js".to_string()));
        assert!(urls.contains(&"https://cdn.example.com/lib.js".to_string()));
    }

    #[test]
    fn extract_sourcemap_url_skips_data_uris_and_resolves_relative_paths() {
        let base = url::Url::parse("https://example.com").unwrap();
        let js_url = "https://example.com/static/app.js";
        assert_eq!(
            extract_sourcemap_url(
                js_url,
                "console.log(1);\n//# sourceMappingURL=app.js.map",
                &base
            ),
            Some("https://example.com/static/app.js.map".into())
        );
        assert_eq!(
            extract_sourcemap_url(
                js_url,
                "//# sourceMappingURL=data:application/json;base64,abcd",
                &base
            ),
            None
        );
    }
}
