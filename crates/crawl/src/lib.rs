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
    clippy::missing_errors_doc,
)]

//! Authenticated web crawler — form extraction, parameter discovery, link following.
//!
//! This scanner uses Headless Chromium to execute JavaScript, evaluate ASTs,
//! and follow Single Page Application links.

pub mod seeds;

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use chromiumoxide::{Browser, BrowserConfig};
use gossan_core::{
    Config, DiscoveredForm, DiscoveredParam, ParamLocation, ParamSource, ScanInput,
    Scanner, Target, WebAssetTarget,
};
use url::Url;

/// Authenticated web crawler that discovers dynamic endpoints via headless browsing.
pub struct CrawlScanner;

#[async_trait]
impl Scanner for CrawlScanner {
    fn name(&self) -> &'static str {
        "crawl"
    }
    fn tags(&self) -> &[&'static str] {
        &["active", "web", "crawl", "headless", "spa"]
    }
    fn accepts(&self, target: &Target) -> bool {
        matches!(target, Target::Web(_))
    }

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<()> {

        let (browser, mut handler) = Browser::launch(
            BrowserConfig::builder()
                .with_head()
                .no_sandbox()
                .build()
                .map_err(|e| anyhow::anyhow!("config error: {e}"))?,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to launch browser: {:?}", e))?;

        let browser = Arc::new(browser);
        let handle = tokio::spawn(async move {
            while let Some(h) = futures::StreamExt::next(&mut handler).await {
                if h.is_err() {
                    break;
                }
            }
        });

        // Drain the streaming inbound channel — `targets: Vec<Target>`
        // is gone; web assets arrive via `target_rx`.
        let web_assets: Vec<WebAssetTarget> = {
            let mut rx = input.target_rx.lock().await;
            let mut out = Vec::new();
            while let Some(t) = rx.recv().await {
                if let Target::Web(w) = t {
                    out.push(*w);
                }
            }
            out
        };

        // Limit concurrent browsers if many targets exist, but here we process sequentially
        for asset in web_assets {
            match crawl_asset(&browser, &asset, config).await {
                Ok(enriched_targets) => {
                    for target in enriched_targets {
                        input.emit_target(Target::Web(Box::new(target.clone())));
                        input.emit_target(Target::Web(Box::new(target)));
                    }
                }
                Err(e) => {
                    tracing::warn!(url = %asset.url, err = %e, "crawl failed for asset");
                }
            }
        }

        handle.abort();
        Ok(())
    }
}

async fn crawl_asset(
    browser: &Arc<Browser>,
    seed: &WebAssetTarget,
    config: &Config,
) -> anyhow::Result<Vec<WebAssetTarget>> {
    let max_pages = config.crawl.max_pages;
    let max_depth = config.crawl.max_depth;
    let base_url = seed.url.clone();
    let base_host = base_url.host_str().unwrap_or("").to_string();

    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: Vec<(Url, usize)> = vec![(base_url.clone(), 0)];
    let mut all_forms: Vec<DiscoveredForm> = Vec::new();
    let mut all_params: Vec<DiscoveredParam> = Vec::new();
    let mut discovered_urls: Vec<Url> = Vec::new();

    while let Some((url, depth)) = queue.pop() {
        if visited.len() >= max_pages {
            break;
        }

        let url_str = url.to_string();
        if !visited.insert(url_str.clone()) {
            continue;
        }

        // Only crawl same-host URLs
        if url.host_str() != Some(&base_host) {
            continue;
        }

        let Ok(page) = browser.new_page(url.as_str()).await else {
            continue;
        };

        let _ = page.goto(url.as_str()).await;
        // Wait for page hydration
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let js_probe = r#"
            (function() {
                const forms = [];
                for (const f of document.forms) {
                    const inputs = [];
                    for (const i of f.elements) {
                        if (i.name) {
                            inputs.push([i.name, i.type || 'text']);
                        }
                    }
                    forms.push({
                        action: f.action || '',
                        method: f.method || 'GET',
                        inputs: inputs
                    });
                }
                const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href);
                return { forms, links, html: document.documentElement.outerHTML };
            })()
        "#;

        if let Ok(res) = page.evaluate(js_probe).await {
            if let Some(val) = res.value() {
                // 1. Process Extracted Forms
                if let Some(forms_arr) = val.get("forms").and_then(|v| v.as_array()) {
                    for f in forms_arr {
                        let action = f.get("action").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let method = f.get("method").and_then(|v| v.as_str()).unwrap_or("GET").to_string();
                        let mut inputs = Vec::new();
                        
                        if let Some(ins) = f.get("inputs").and_then(|v| v.as_array()) {
                            for i in ins {
                                if let Some(pair) = i.as_array() {
                                    let name = pair.first().and_then(|v| v.as_str()).unwrap_or("").to_string();
                                    let typ = pair.get(1).and_then(|v| v.as_str()).unwrap_or("text").to_string();
                                    inputs.push((name, typ));
                                }
                            }
                        }

                        let df = DiscoveredForm { action, method, inputs };
                        if !all_forms.iter().any(|existing| existing.action == df.action && existing.method == df.method) {
                            for (name, _t) in &df.inputs {
                                if !all_params.iter().any(|p| p.name == *name) {
                                    all_params.push(DiscoveredParam {
                                        name: name.clone(),
                                        location: if df.method.eq_ignore_ascii_case("POST") { ParamLocation::Body } else { ParamLocation::Query },
                                        source: ParamSource::HtmlForm,
                                    });
                                }
                            }
                            all_forms.push(df);
                        }
                    }
                }

                // 2. Process DOM Links
                if depth < max_depth {
                    if let Some(links_arr) = val.get("links").and_then(|v| v.as_array()) {
                        for l in links_arr {
                            if let Some(href) = l.as_str() {
                                if let Ok(u) = Url::parse(href) {
                                    if u.host_str() == Some(&base_host) && !visited.contains(u.as_str()) {
                                        discovered_urls.push(u.clone());
                                        queue.push((u, depth + 1));
                                    }
                                }
                            }
                        }
                    }
                }

                // 3. Process AST JavaScript Endpoints using gossan-js!
                if let Some(html) = val.get("html").and_then(|v| v.as_str()) {
                    let js_endpoints = gossan_js::endpoints::extract(url.as_str(), html);
                    for ep in js_endpoints {
                        // resolve relative paths to full url
                        let ep_url = Url::parse(&ep.path)
                            .ok()
                            .or_else(|| url.join(&ep.path).ok());

                        if let Some(u) = ep_url {
                            if u.host_str() == Some(&base_host) && !visited.contains(u.as_str()) {
                                discovered_urls.push(u.clone());
                                if depth < max_depth {
                                    queue.push((u, depth + 1));
                                }
                            }
                        }
                    }
                }
            }
        }

        page.close().await.ok();
    }

    tracing::info!(
        seed = %seed.url,
        pages = visited.len(),
        forms = all_forms.len(),
        params = all_params.len(),
        links = discovered_urls.len(),
        "headless crawl complete"
    );

    let mut results = Vec::new();
    let mut enriched_seed = seed.clone();
    enriched_seed.forms = all_forms;
    enriched_seed.params = all_params;
    results.push(enriched_seed);

    for url in discovered_urls {
        if url.as_str() == seed.url.as_str() {
            continue;
        }
        results.push(WebAssetTarget {
            url,
            service: seed.service.clone(),
            tech: vec![],
            status: 0,
            title: None,
            favicon_hash: None,
            body_hash: None,
            forms: vec![],
            params: vec![],
        });
    }

    Ok(results)
}
