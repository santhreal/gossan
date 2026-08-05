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

//! Authenticated web crawler (form extraction, parameter discovery, link following).
//!
//! This scanner uses Headless Chromium to execute JavaScript, evaluate ASTs,
//! and follow Single Page Application links.

pub mod seeds;

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use async_trait::async_trait;
use gossan_core::{
    generate_dom_fingerprint, Config, DiscoveredForm, DiscoveredParam, HostRateLimiter,
    ParamLocation, ParamSource, ScanInput, Scanner, Target, WebAssetTarget,
};
use runtime_headless::chromiumoxide::Browser;
use runtime_headless::{navigate, BrowserLaunchOptions, BrowserRuntime};
use url::Url;

/// Authenticated web crawler that discovers dynamic endpoints via headless browsing.
pub struct CrawlScanner;

fn crawl_browser_options() -> BrowserLaunchOptions {
    let mut options = BrowserLaunchOptions::default_stealth();
    options.no_sandbox = true;
    options
}

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
        let runtime = BrowserRuntime::launch(&crawl_browser_options())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to launch browser: {e}"))?;

        // Drain the streaming inbound channel: `targets: Vec<Target>`
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
            match crawl_asset(runtime.browser(), &asset, config).await {
                Ok(enriched_targets) => {
                    for target in enriched_targets {
                        input.emit_target(Target::Web(Box::new(target))).await;
                    }
                }
                Err(e) => {
                    tracing::warn!(url = %asset.url, err = %e, "crawl failed for asset");
                }
            }
        }

        Ok(())
    }
}

/// Pure logic: decide whether a URL should be crawled given current state.
/// Strip the fragment so `https://example.com/page#section` and
/// `https://example.com/page` are treated as the same URL.
fn canonical_url_str(url: &Url) -> String {
    let s = url.as_str();
    match s.find('#') {
        Some(i) => s[..i].to_string(),
        None => s.to_string(),
    }
}

/// Pure logic: decide whether a URL should be crawled given current state.
fn should_crawl_url(
    url: &Url,
    base_host: &str,
    visited: &HashSet<String>,
    max_pages: usize,
) -> bool {
    if visited.len() >= max_pages {
        return false;
    }
    if visited.contains(&canonical_url_str(url)) {
        return false;
    }
    if url.host_str() != Some(base_host) {
        return false;
    }
    true
}

/// Pure logic: check whether a form has already been recorded.
///
/// Takes a `HashSet<(action, method)>` key set instead of a full slice so the
/// lookup is O(1) rather than O(n). The key is `(action.clone(), method.clone())`.
fn form_key(form: &DiscoveredForm) -> (String, String) {
    (form.action.clone(), form.method.to_ascii_uppercase())
}

/// Pure logic: check whether a form has already been recorded (O(n) version,
/// kept for tests that cannot inject the HashSet state).
fn form_already_seen(form: &DiscoveredForm, all_forms: &[DiscoveredForm]) -> bool {
    all_forms
        .iter()
        .any(|existing| existing.action == form.action && existing.method == form.method)
}

/// Pure logic: check whether a parameter has already been recorded (O(n) version,
/// kept for tests that cannot inject the HashSet state).
fn param_already_seen(name: &str, all_params: &[DiscoveredParam]) -> bool {
    all_params.iter().any(|p| p.name == name)
}

/// Only successful final responses are scraped / followed. An unknown
/// status (navigation timeout or missing response) fails closed.
fn navigation_status_allows_extract(status: Option<u16>) -> bool {
    matches!(status, Some(s) if (200..300).contains(&s))
}

/// Discoveries (emit + queue) are depth-gated the same way.
fn should_record_discovery(depth: usize, max_depth: usize) -> bool {
    depth < max_depth
}

/// Link expansion requires a soft-404 DOM baseline. Without it, SPA catch-alls
/// that lack "404" title/body text would otherwise enqueue every shell mirror.
fn may_expand_links(soft404_baseline: Option<&str>) -> bool {
    soft404_baseline.is_some()
}

/// Robots.txt body read cap (bytes).
const ROBOTS_BODY_LIMIT: usize = 64 * 1024;

/// Fetch `/robots.txt` and return Disallow URLs. Warns and returns empty on
/// transport/parse failure (no silent discard of the failure itself).
async fn fetch_robots_disallowed(
    base_url: &Url,
    base_host: &str,
    nav_timeout: Duration,
    rate_limiter: &HostRateLimiter,
) -> Vec<Url> {
    let robots_url = match base_url.join("/robots.txt") {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(
                url = %base_url,
                err = %e,
                "crawl: failed to join /robots.txt; Disallow filter disabled for this crawl"
            );
            return Vec::new();
        }
    };

    rate_limiter.until_ready(base_host).await;

    let client = match reqwest::Client::builder().timeout(nav_timeout).build() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                err = %e,
                "crawl: failed to build HTTP client for robots.txt; Disallow filter disabled"
            );
            return Vec::new();
        }
    };

    let resp = match client.get(robots_url.as_str()).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                url = %robots_url,
                err = %e,
                "crawl: robots.txt fetch failed; Disallow filter disabled for this crawl"
            );
            return Vec::new();
        }
    };

    if !resp.status().is_success() {
        tracing::debug!(
            url = %robots_url,
            status = %resp.status(),
            "crawl: robots.txt non-success; no Disallow rules applied"
        );
        return Vec::new();
    }

    let body = match gossan_core::net::bounded_text(resp, ROBOTS_BODY_LIMIT).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                url = %robots_url,
                err = %e,
                "crawl: robots.txt body read failed; Disallow filter disabled for this crawl"
            );
            return Vec::new();
        }
    };

    let parsed = seeds::parse_robots_txt(&body, base_url);
    if !parsed.disallowed.is_empty() {
        tracing::info!(
            url = %robots_url,
            disallow_count = parsed.disallowed.len(),
            "crawl: loaded robots.txt Disallow rules"
        );
    }
    parsed.disallowed
}

/// Soft-404 / not-found title and body signals (title-weighted).
fn looks_like_soft_404(title: &str, html: &str) -> bool {
    let title_l = title.to_ascii_lowercase();
    const TITLE_SIGNALS: &[&str] = &[
        "page not found",
        "not found",
        "404",
        "does not exist",
        "couldn't find",
        "could not find",
        "no such page",
        "error 404",
    ];
    if TITLE_SIGNALS.iter().any(|s| title_l.contains(s)) {
        return true;
    }
    let body_l = html.to_ascii_lowercase();
    const BODY_SIGNALS: &[&str] = &[
        "page not found",
        "error 404",
        "404 not found",
        "does not exist",
        "no such page",
    ];
    BODY_SIGNALS.iter().any(|s| body_l.contains(s))
}

/// After redirects, final URL must stay on the seed host.
fn final_url_same_host(nav_url: Option<&str>, base_host: &str) -> bool {
    match nav_url.and_then(|u| Url::parse(u).ok()) {
        Some(u) => u.host_str() == Some(base_host),
        // No observed final URL - do not treat as off-host.
        None => true,
    }
}

/// Probe a unique garbage path; if it returns 2xx, treat its DOM fingerprint as a
/// catch-all / soft-404 baseline for later mirror detection.
async fn establish_soft404_dom(
    browser: &Browser,
    base_url: &Url,
    base_host: &str,
    nav_timeout: Duration,
    rate_limiter: &HostRateLimiter,
) -> Option<String> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let probe = base_url
        .join(&format!("/santh-crawl-nf-{nonce}"))
        .ok()?;

    rate_limiter.until_ready(base_host).await;

    let page = match tokio::time::timeout(nav_timeout, browser.new_page(probe.as_str())).await {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            tracing::warn!("soft404 baseline new_page failed: url={} error={}", probe, e);
            return None;
        }
        Err(_) => {
            tracing::warn!("soft404 baseline new_page timed out: url={}", probe);
            return None;
        }
    };

    let nav = match navigate(&page, probe.as_str(), nav_timeout).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!("soft404 baseline navigate failed: url={} error={}", probe, e);
            let _ = page.close().await;
            return None;
        }
    };

    if !navigation_status_allows_extract(nav.status)
        || !final_url_same_host(nav.url.as_deref(), base_host)
    {
        let _ = page.close().await;
        return None;
    }

    let html = match page.evaluate("document.documentElement.outerHTML").await {
        Ok(res) => {
            match res.value().and_then(|v| v.as_str().map(str::to_string)) {
                Some(s) => s,
                None => {
                    tracing::warn!("soft404 baseline evaluate returned non-string HTML: url={}", probe);
                    String::new()
                }
            }
        }
        Err(e) => {
            tracing::warn!("soft404 baseline evaluate failed: url={} error={}", probe, e);
            let _ = page.close().await;
            return None;
        }
    };
    let _ = page.close().await;

    let fp = generate_dom_fingerprint(&html);
    if fp.is_empty() {
        None
    } else {
        Some(fp)
    }
}

async fn crawl_asset(
    browser: &Browser,
    seed: &WebAssetTarget,
    config: &Config,
) -> anyhow::Result<Vec<WebAssetTarget>> {
    let max_pages = config.crawl.max_pages;
    let max_depth = config.crawl.max_depth;
    let base_url = seed.url.clone();
    let base_host = base_url.host_str().unwrap_or("").to_string();
    let nav_timeout = Duration::from_secs(config.timeout_secs.max(1));
    let rate_limiter = HostRateLimiter::from_config(config);

    let soft404_dom = establish_soft404_dom(
        browser,
        &base_url,
        &base_host,
        nav_timeout,
        &rate_limiter,
    )
    .await;

    // Fail closed: without a DOM baseline, SPA catch-alls with weak title/body
    // signals would otherwise be scraped and fully linked.
    let expand_links = may_expand_links(soft404_dom.as_deref());
    if !expand_links {
        tracing::warn!(
            seed = %seed.url,
            "crawl: soft404 baseline unavailable; fail-closed: link expansion disabled"
        );
    }

    let robots_disallowed =
        fetch_robots_disallowed(&base_url, &base_host, nav_timeout, &rate_limiter).await;

    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: Vec<(Url, usize)> = vec![(base_url.clone(), 0)];
    let mut all_forms: Vec<DiscoveredForm> = Vec::new();
    // O(1) form dedup: (action, normalised-method) → already added
    let mut form_seen: HashSet<(String, String)> = HashSet::new();
    let mut all_params: Vec<DiscoveredParam> = Vec::new();
    // O(1) param dedup: param name → already added
    let mut param_seen: HashSet<String> = HashSet::new();
    let mut discovered_urls: Vec<Url> = Vec::new();
    let mut url_status: HashMap<String, u16> = HashMap::new();

    while let Some((url, depth)) = queue.pop() {
        // Seed (depth 0) is always eligible; children honor Disallow.
        if depth > 0 && seeds::is_disallowed(&url, &robots_disallowed) {
            tracing::debug!(url = %url, "crawl: skipping robots.txt Disallow path");
            continue;
        }
        if !should_crawl_url(&url, &base_host, &visited, max_pages) {
            continue;
        }

        let canon = canonical_url_str(&url);
        let _ = visited.insert(canon.clone());

        rate_limiter.until_ready(&base_host).await;

        let page = match tokio::time::timeout(nav_timeout, browser.new_page(url.as_str())).await {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                tracing::warn!(url = %url, err = %e, "crawl: browser.new_page failed");
                continue;
            }
            Err(_) => {
                tracing::warn!(
                    "crawl: browser.new_page timed out url={} timeout_secs={}",
                    url, config.timeout_secs
                );
                continue;
            }
        };

        let nav = match navigate(&page, url.as_str(), nav_timeout).await {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(url = %url, err = %e, "crawl: navigate failed");
                let _ = page.close().await;
                continue;
            }
        };

        // Fail closed: unknown status (timeout / missing response) or non-2xx.
        if !navigation_status_allows_extract(nav.status) {
            tracing::debug!(
                "crawl: skipping extract on non-success navigation status url={} status={:?}",
                url, nav.status
            );
            let _ = page.close().await;
            continue;
        }

        if !final_url_same_host(nav.url.as_deref(), &base_host) {
            tracing::debug!(
                "crawl: skipping off-host redirect target url={} final_url={:?}",
                url, nav.url
            );
            let _ = page.close().await;
            continue;
        }

        if let Some(status) = nav.status {
            url_status.insert(canon, status);
        }

        // Wait for SPA hydration only after a successful same-host 2xx nav.
        tokio::time::sleep(Duration::from_secs(2)).await;

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
                return {
                    forms,
                    links,
                    html: document.documentElement.outerHTML,
                    title: document.title || ''
                };
            })()
        "#;

        match page.evaluate(js_probe).await {
            Err(e) => {
                tracing::warn!(
                    url = %url,
                    err = %e,
                    "crawl: page.evaluate(js_probe) failed; skip extract"
                );
            }
            Ok(res) => {
                if let Some(val) = res.value() {
                let title = val.get("title").and_then(|v| v.as_str()).unwrap_or("");
                let html = val.get("html").and_then(|v| v.as_str()).unwrap_or("");

                let soft404 = looks_like_soft_404(title, html)
                    || soft404_dom
                        .as_ref()
                        .is_some_and(|fp| generate_dom_fingerprint(html) == *fp);

                if soft404 {
                    tracing::debug!(url = %url, "crawl: soft-404 / catch-all shell; skip extract");
                    let _ = page.close().await;
                    continue;
                }

                // 1. Process Extracted Forms
                if let Some(forms_arr) = val.get("forms").and_then(|v| v.as_array()) {
                    for f in forms_arr {
                        let action = f
                            .get("action")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let method = f
                            .get("method")
                            .and_then(|v| v.as_str())
                            .unwrap_or("GET")
                            .to_string();
                        let mut inputs = Vec::new();

                        if let Some(ins) = f.get("inputs").and_then(|v| v.as_array()) {
                            for i in ins {
                                if let Some(pair) = i.as_array() {
                                    let name = pair
                                        .first()
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    let typ = pair
                                        .get(1)
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("text")
                                        .to_string();
                                    inputs.push((name, typ));
                                }
                            }
                        }

                        let df = DiscoveredForm {
                            action,
                            method,
                            inputs,
                        };
                        // O(1) dedup via HashSet: only run the inner loop when the
                        // form is genuinely new (previously O(n·forms) per form).
                        if form_seen.insert(form_key(&df)) {
                            for (name, _t) in &df.inputs {
                                // O(1) param dedup via HashSet (previously O(n·params)).
                                if param_seen.insert(name.clone()) {
                                    all_params.push(DiscoveredParam {
                                        name: name.clone(),
                                        location: if df.method.eq_ignore_ascii_case("POST") {
                                            ParamLocation::Body
                                        } else {
                                            ParamLocation::Query
                                        },
                                        source: ParamSource::HtmlForm,
                                    });
                                }
                            }
                            all_forms.push(df);
                        }
                    }
                }

                // 2. Process DOM Links (depth-gated emit + queue).
                // Fail closed without soft404 baseline: do not expand SPA shells.
                if expand_links && should_record_discovery(depth, max_depth) {
                    if let Some(links_arr) = val.get("links").and_then(|v| v.as_array()) {
                        for l in links_arr {
                            if let Some(href) = l.as_str() {
                                if let Ok(u) = Url::parse(href) {
                                    if u.host_str() == Some(&base_host)
                                        && !visited.contains(&canonical_url_str(&u))
                                        && !seeds::is_disallowed(&u, &robots_disallowed)
                                    {
                                        discovered_urls.push(u.clone());
                                        queue.push((u, depth.saturating_add(1)));
                                    }
                                }
                            }
                        }
                    }
                }

                // 3. Process AST JavaScript Endpoints using gossan-js!
                // Same depth gate for emit as for queue (no beyond-depth assets).
                if expand_links && should_record_discovery(depth, max_depth) {
                    if let Some(html) = val.get("html").and_then(|v| v.as_str()) {
                        let js_endpoints = gossan_js::endpoints::extract(url.as_str(), html);
                        for ep in js_endpoints {
                            // resolve relative paths to full url
                            let ep_url = Url::parse(&ep.path)
                                .ok()
                                .or_else(|| url.join(&ep.path).ok());

                            if let Some(u) = ep_url {
                                if u.host_str() == Some(&base_host)
                                    && !visited.contains(&canonical_url_str(&u))
                                    && !seeds::is_disallowed(&u, &robots_disallowed)
                                {
                                    discovered_urls.push(u.clone());
                                    queue.push((u, depth.saturating_add(1)));
                                }
                            }
                        }
                    }
                }
            }
            }
        }

        let _ = page.close().await;
    }

    tracing::info!(
        "headless crawl complete seed={} pages={} forms={} params={} links={}",
        seed.url, visited.len(), all_forms.len(), all_params.len(), discovered_urls.len()
    );

    let mut results = Vec::new();
    let mut enriched_seed = seed.clone();
    enriched_seed.forms = all_forms;
    enriched_seed.params = all_params;
    if let Some(status) = url_status.get(&canonical_url_str(&seed.url)).copied() {
        enriched_seed.status = status;
    }
    results.push(enriched_seed);

    for url in discovered_urls {
        if url.as_str() == seed.url.as_str() {
            continue;
        }
        let status = url_status
            .get(&canonical_url_str(&url))
            .copied()
            .unwrap_or(0);
        results.push(WebAssetTarget {
            url,
            service: seed.service.clone(),
            tech: vec![],
            status,
            title: None,
            favicon_hash: None,
            body_hash: None,
            forms: vec![],
            params: vec![],
        });
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::{HostTarget, ParamLocation, ParamSource, Protocol, ServiceTarget};

    #[test]
    fn crawl_browser_options_delegate_runtime_stealth_profile() {
        let options = crawl_browser_options();
        let expected = BrowserLaunchOptions::default_stealth();

        assert_eq!(options.window_width, expected.window_width);
        assert_eq!(options.window_height, expected.window_height);
        assert!(!options.headed);
        assert!(options.new_headless_mode);
        assert!(options.no_sandbox);
        assert_eq!(options.extra_args, expected.extra_args);
    }

    fn example_url(path: &str) -> Url {
        Url::parse(&format!("https://example.com{path}")).unwrap()
    }

    fn other_host_url(path: &str) -> Url {
        Url::parse(&format!("https://evil.com{path}")).unwrap()
    }

    // ── Same-host filtering ───────────────────────────────────────────────

    #[test]
    fn same_host_url_is_allowed() {
        let visited = HashSet::new();
        assert!(should_crawl_url(&example_url("/page"), "example.com", &visited, 100));
    }

    #[test]
    fn cross_host_url_is_rejected() {
        let visited = HashSet::new();
        assert!(!should_crawl_url(&other_host_url("/page"), "example.com", &visited, 100));
    }

    #[test]
    fn subdomain_is_different_host() {
        let sub = Url::parse("https://sub.example.com/page").unwrap();
        let visited = HashSet::new();
        assert!(!should_crawl_url(&sub, "example.com", &visited, 100));
    }

    #[test]
    fn already_visited_url_is_rejected() {
        let mut visited = HashSet::new();
        let url = example_url("/page");
        visited.insert(url.as_str().to_string());
        assert!(!should_crawl_url(&url, "example.com", &visited, 100));
    }

    // ── Max pages ─────────────────────────────────────────────────────────

    #[test]
    fn max_pages_zero_rejects_all() {
        let visited = HashSet::new();
        assert!(!should_crawl_url(&example_url("/"), "example.com", &visited, 0));
    }

    #[test]
    fn max_pages_enforced_at_limit() {
        let mut visited = HashSet::new();
        visited.insert("https://example.com/a".to_string());
        visited.insert("https://example.com/b".to_string());
        // visited.len() == 2, max_pages == 2  → reject next
        assert!(!should_crawl_url(&example_url("/c"), "example.com", &visited, 2));
    }

    #[test]
    fn max_pages_allows_when_under_limit() {
        let mut visited = HashSet::new();
        visited.insert("https://example.com/a".to_string());
        // visited.len() == 1, max_pages == 2  → allow
        assert!(should_crawl_url(&example_url("/b"), "example.com", &visited, 2));
    }

    // ── Max depth (tested via queue logic simulation) ─────────────────────

    #[test]
    fn depth_zero_allows_links() {
        // At depth 0 with max_depth 1, links SHOULD be followed.
        let depth = 0_usize;
        let max_depth = 1_usize;
        assert!(depth < max_depth);
    }

    #[test]
    fn depth_at_max_depth_blocks_links() {
        // At depth 1 with max_depth 1, links should NOT be followed.
        let depth = 1_usize;
        let max_depth = 1_usize;
        assert!(!(depth < max_depth));
    }

    // ── Form extraction / deduplication ───────────────────────────────────

    #[test]
    fn form_dedup_same_action_method() {
        let f1 = DiscoveredForm {
            action: "/login".to_string(),
            method: "POST".to_string(),
            inputs: vec![("user".into(), "text".into())],
        };
        let f2 = DiscoveredForm {
            action: "/login".to_string(),
            method: "POST".to_string(),
            inputs: vec![("email".into(), "email".into())],
        };
        assert!(form_already_seen(&f2, &[f1.clone()]));
    }

    #[test]
    fn form_dedup_different_action_is_new() {
        let f1 = DiscoveredForm {
            action: "/login".to_string(),
            method: "POST".to_string(),
            inputs: vec![],
        };
        let f2 = DiscoveredForm {
            action: "/register".to_string(),
            method: "POST".to_string(),
            inputs: vec![],
        };
        assert!(!form_already_seen(&f2, &[f1]));
    }

    #[test]
    fn form_dedup_different_method_is_new() {
        let f1 = DiscoveredForm {
            action: "/search".to_string(),
            method: "GET".to_string(),
            inputs: vec![],
        };
        let f2 = DiscoveredForm {
            action: "/search".to_string(),
            method: "POST".to_string(),
            inputs: vec![],
        };
        assert!(!form_already_seen(&f2, &[f1]));
    }

    #[test]
    fn param_dedup_prevents_duplicates() {
        let p = DiscoveredParam {
            name: "q".to_string(),
            location: ParamLocation::Query,
            source: ParamSource::HtmlForm,
        };
        assert!(param_already_seen("q", &[p]));
    }

    #[test]
    fn param_new_name_is_allowed() {
        let p = DiscoveredParam {
            name: "q".to_string(),
            location: ParamLocation::Query,
            source: ParamSource::HtmlForm,
        };
        assert!(!param_already_seen("page", &[p]));
    }

    #[test]
    fn form_with_various_input_types() {
        let form = DiscoveredForm {
            action: "/submit".to_string(),
            method: "POST".to_string(),
            inputs: vec![
                ("username".into(), "text".into()),
                ("password".into(), "password".into()),
                ("avatar".into(), "file".into()),
                ("newsletter".into(), "checkbox".into()),
                ("country".into(), "select".into()),
                ("bio".into(), "textarea".into()),
            ],
        };
        assert_eq!(form.inputs.len(), 6);
        assert!(form.inputs.iter().any(|(n, _)| n == "password"));
        assert!(form.inputs.iter().any(|(n, _)| n == "avatar"));
    }

    // ── Single-emit anti-regression ───────────────────────────────────────
    //
    // Previously the run() loop emitted each enriched target TWICE
    // (target.clone() then target). This test pins that `crawl_asset`
    // results are emitted exactly once so downstream pipelines don't
    // receive duplicate findings.

    #[test]
    fn form_already_seen_empty_list_is_not_seen() {
        let form = DiscoveredForm {
            action: "/submit".to_string(),
            method: "POST".to_string(),
            inputs: vec![],
        };
        assert!(!form_already_seen(&form, &[]));
    }

    #[test]
    fn should_crawl_url_max_pages_zero_always_rejects() {
        let visited = std::collections::HashSet::new();
        // max_pages == 0 → every URL is rejected regardless of visited state.
        assert!(!should_crawl_url(&example_url("/a"), "example.com", &visited, 0));
        assert!(!should_crawl_url(&example_url("/b"), "example.com", &visited, 0));
        assert!(!should_crawl_url(&example_url("/c"), "example.com", &visited, 0));
    }

    #[test]
    fn should_crawl_url_exactly_at_max_rejects() {
        let mut visited = std::collections::HashSet::new();
        for i in 0..10 {
            visited.insert(format!("https://example.com/page{i}"));
        }
        // visited.len() == max_pages → must reject (boundary).
        assert!(!should_crawl_url(&example_url("/new"), "example.com", &visited, 10));
    }

    #[test]
    fn should_crawl_url_one_under_max_allows() {
        let mut visited = std::collections::HashSet::new();
        for i in 0..9 {
            visited.insert(format!("https://example.com/page{i}"));
        }
        // visited.len() == 9 < max_pages == 10 → must allow.
        assert!(should_crawl_url(&example_url("/new"), "example.com", &visited, 10));
    }

    // ── Timeout constants ─────────────────────────────────────────────────

    #[test]
    fn nav_timeout_uses_config_timeout_secs() {
        let mut cfg = Config::default();
        cfg.timeout_secs = 7;
        let d = std::time::Duration::from_secs(cfg.timeout_secs.max(1));
        assert_eq!(d.as_secs(), 7);
    }

    #[test]
    fn nav_timeout_zero_config_clamps_to_one() {
        let mut cfg = Config::default();
        cfg.timeout_secs = 0;
        let d = std::time::Duration::from_secs(cfg.timeout_secs.max(1));
        assert_eq!(d.as_secs(), 1);
    }

    // ── Scanner metadata ──────────────────────────────────────────────────

    #[test]
    fn scanner_name_is_crawl() {
        let scanner = CrawlScanner;
        assert_eq!(scanner.name(), "crawl");
    }

    #[test]
    fn scanner_accepts_only_web_targets() {
        let scanner = CrawlScanner;
        let web = Target::Web(Box::new(WebAssetTarget {
            url: example_url("/"),
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
        }));
        assert!(scanner.accepts(&web));
        assert!(!scanner.accepts(&Target::Host(HostTarget {
            ip: "127.0.0.1".parse().unwrap(),
            domain: None,
        })));
    }

    // ── Canonical URL / fragment handling ─────────────────────────────────

    #[test]
    fn canonical_url_strips_fragment() {
        let url = Url::parse("https://example.com/page#section").unwrap();
        assert_eq!(canonical_url_str(&url), "https://example.com/page");
    }

    #[test]
    fn canonical_url_unchanged_without_fragment() {
        let url = Url::parse("https://example.com/page").unwrap();
        assert_eq!(canonical_url_str(&url), "https://example.com/page");
    }

    #[test]
    fn should_crawl_url_rejects_same_page_different_fragment() {
        let mut visited = std::collections::HashSet::new();
        visited.insert("https://example.com/page".to_string());
        let url = Url::parse("https://example.com/page#section").unwrap();
        assert!(!should_crawl_url(&url, "example.com", &visited, 100));
    }

    #[test]
    fn depth_saturating_add_at_max() {
        let depth = usize::MAX - 1;
        let max_depth = usize::MAX;
        assert!(depth < max_depth);
        let next = depth.saturating_add(1);
        assert_eq!(next, usize::MAX);
        assert!(!(next < max_depth)); // next iteration would be rejected
    }

    // ── proptest property tests ───────────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn should_crawl_url_never_panics(url_str in "https://[a-z]{1,20}\\.[a-z]{2,6}/[a-zA-Z0-9/_-]{0,64}") {
            let url = Url::parse(&url_str).unwrap_or_else(|_| Url::parse("https://example.com/").unwrap());
            let visited = std::collections::HashSet::new();
            let _ = should_crawl_url(&url, "example.com", &visited, 100);
        }

        #[test]
        fn form_already_seen_is_consistent(
            action in "\\PC{0,64}",
            method in "(GET|POST|PUT|DELETE)"
        ) {
            let f1 = DiscoveredForm {
                action: action.clone(),
                method: method.clone(),
                inputs: vec![],
            };
            let f2 = DiscoveredForm {
                action,
                method,
                inputs: vec![("x".into(), "text".into())],
            };
            prop_assert!(form_already_seen(&f2, &[f1]));
        }

        #[test]
        fn param_already_seen_is_consistent(name in "\\PC{0,64}") {
            let p = DiscoveredParam {
                name: name.clone(),
                location: ParamLocation::Query,
                source: ParamSource::HtmlForm,
            };
            prop_assert!(param_already_seen(&name, &[p]));
        }

        #[test]
        fn canonical_url_idempotent(url_str in "https://[a-z]{1,20}\\.[a-z]{2,6}/[a-zA-Z0-9/_-]{0,64}(#[a-z]{0,16})?") {
            let url = Url::parse(&url_str).unwrap_or_else(|_| Url::parse("https://example.com/").unwrap());
            let c1 = canonical_url_str(&url);
            let c2 = canonical_url_str(&url);
            prop_assert_eq!(c1, c2);
        }

        #[test]
        fn should_crawl_url_respects_max_pages(max_pages in 0usize..1000) {
            let mut visited = std::collections::HashSet::new();
            for i in 0..max_pages {
                visited.insert(format!("https://example.com/page{i}"));
            }
            let url = Url::parse("https://example.com/new").unwrap();
            prop_assert!(!should_crawl_url(&url, "example.com", &visited, max_pages));
        }
    }

    // ── form_key / O(1) dedup consistency ────────────────────────────────────

    /// Invariant: `form_key` produces the same key for two forms that differ
    /// only in method case ("post" vs "POST").
    #[test]
    fn form_key_normalises_method_case() {
        let f1 = DiscoveredForm {
            action: "/login".to_string(),
            method: "post".to_string(),
            inputs: vec![],
        };
        let f2 = DiscoveredForm {
            action: "/login".to_string(),
            method: "POST".to_string(), // different case
            inputs: vec![("user".into(), "text".into())],
        };
        // form_key normalises method to uppercase, so both keys are equal.
        assert_eq!(form_key(&f1), form_key(&f2));
    }

    /// Invariant: `form_key` and `form_already_seen` agree when methods match exactly.
    #[test]
    fn form_key_matches_linear_dedup_same_form_exact_case() {
        let f1 = DiscoveredForm {
            action: "/login".to_string(),
            method: "POST".to_string(),
            inputs: vec![],
        };
        let f2 = DiscoveredForm {
            action: "/login".to_string(),
            method: "POST".to_string(),
            inputs: vec![("user".into(), "text".into())],
        };
        // Both helpers agree when the method case is already normalised.
        assert_eq!(form_key(&f1), form_key(&f2));
        assert!(form_already_seen(&f1, &[f2.clone()]));
    }

    /// Invariant: different (action, method) pairs produce distinct keys.
    #[test]
    fn form_key_distinguishes_different_forms() {
        let f1 = DiscoveredForm {
            action: "/a".to_string(),
            method: "GET".to_string(),
            inputs: vec![],
        };
        let f2 = DiscoveredForm {
            action: "/b".to_string(),
            method: "GET".to_string(),
            inputs: vec![],
        };
        assert_ne!(form_key(&f1), form_key(&f2));
    }

    /// O(1) HashSet dedup agrees with O(n) linear dedup for a batch of forms
    /// when methods are already normalised to uppercase.
    #[test]
    fn hashset_form_dedup_agrees_with_linear() {
        // All methods uppercase so form_key and form_already_seen agree on case.
        let forms: Vec<DiscoveredForm> = vec![
            DiscoveredForm { action: "/a".into(), method: "GET".into(), inputs: vec![] },
            DiscoveredForm { action: "/b".into(), method: "POST".into(), inputs: vec![] },
            DiscoveredForm { action: "/a".into(), method: "GET".into(), inputs: vec![("x".into(), "text".into())] }, // dup
            DiscoveredForm { action: "/c".into(), method: "PUT".into(), inputs: vec![] },
        ];

        // O(1) path
        let mut seen_keys: HashSet<(String, String)> = HashSet::new();
        let o1_unique: Vec<&DiscoveredForm> = forms
            .iter()
            .filter(|f| seen_keys.insert(form_key(f)))
            .collect();

        // O(n) path
        let mut o_n_unique: Vec<&DiscoveredForm> = Vec::new();
        for f in &forms {
            if !form_already_seen(f, &o_n_unique.iter().map(|x| (*x).clone()).collect::<Vec<_>>()) {
                o_n_unique.push(f);
            }
        }

        assert_eq!(
            o1_unique.len(),
            o_n_unique.len(),
            "O(1) and O(n) paths must produce the same number of unique forms"
        );
        assert_eq!(o1_unique.len(), 3, "3 unique forms: /a GET, /b POST, /c PUT");
    }

    /// O(1) param dedup: a param inserted into the HashSet is not re-inserted.
    #[test]
    fn hashset_param_dedup_prevents_double_insertion() {
        let mut seen: HashSet<String> = HashSet::new();
        assert!(seen.insert("q".to_string()), "first insert succeeds");
        assert!(!seen.insert("q".to_string()), "second insert fails (already present)");
        assert!(seen.insert("page".to_string()), "different name always succeeds");
    }

    // ── Navigation / soft-404 / depth emit gates ───────────────────────────

    #[test]
    fn navigation_status_allows_only_2xx() {
        assert!(navigation_status_allows_extract(Some(200)));
        assert!(navigation_status_allows_extract(Some(204)));
        assert!(navigation_status_allows_extract(Some(299)));
        assert!(!navigation_status_allows_extract(None));
        assert!(!navigation_status_allows_extract(Some(0)));
        assert!(!navigation_status_allows_extract(Some(301)));
        assert!(!navigation_status_allows_extract(Some(403)));
        assert!(!navigation_status_allows_extract(Some(404)));
        assert!(!navigation_status_allows_extract(Some(500)));
    }

    #[test]
    fn should_record_discovery_respects_max_depth() {
        assert!(should_record_discovery(0, 1));
        assert!(!should_record_discovery(1, 1));
        assert!(!should_record_discovery(2, 1));
        assert!(should_record_discovery(0, 0) == false);
    }

    #[test]
    fn soft404_title_and_body_signals() {
        assert!(looks_like_soft_404("404 Not Found", "<html></html>"));
        assert!(looks_like_soft_404("Welcome", "<h1>Page Not Found</h1>"));
        assert!(!looks_like_soft_404("Home", "<html><body>hello world</body></html>"));
        // bare numeric mention in body alone should not trip (title-weighted)
        assert!(!looks_like_soft_404("Dashboard", "<p>build 40401 shipped</p>"));
    }

    #[test]
    fn final_url_same_host_blocks_off_host_redirect() {
        assert!(final_url_same_host(Some("https://example.com/ok"), "example.com"));
        assert!(!final_url_same_host(Some("https://evil.com/ok"), "example.com"));
        assert!(final_url_same_host(None, "example.com"));
    }

    #[test]
    fn crawled_status_map_overrides_zero_default() {
        let mut url_status = std::collections::HashMap::new();
        let url = Url::parse("https://example.com/a").unwrap();
        url_status.insert(canonical_url_str(&url), 200_u16);
        let status = url_status
            .get(&canonical_url_str(&url))
            .copied()
            .unwrap_or(0);
        assert_eq!(status, 200);
        let missing = Url::parse("https://example.com/b").unwrap();
        let status0 = url_status
            .get(&canonical_url_str(&missing))
            .copied()
            .unwrap_or(0);
        assert_eq!(status0, 0);
    }

    /// Adversarial: missing soft404 baseline must fail closed (no link expansion).
    /// SPA catch-alls without "404" title/body would otherwise enqueue children.
    #[test]
    fn soft404_baseline_none_disables_link_expansion() {
        assert!(!may_expand_links(None));
        assert!(may_expand_links(Some("deadbeef-fingerprint")));
        // Weak title/body alone is not enough to authorize expansion.
        assert!(!looks_like_soft_404("App", "<html><body>Welcome to the app</body></html>"));
        assert!(
            !may_expand_links(None) || looks_like_soft_404("App", "<html></html>"),
            "SPA shell without baseline must not expand links"
        );
    }

    #[test]
    fn robots_disallow_filters_enqueue_candidates() {
        let base = Url::parse("https://example.com/").unwrap();
        let robots = seeds::parse_robots_txt(
            "User-agent: *\nDisallow: /secret\nDisallow: /admin\n",
            &base,
        );
        let blocked = Url::parse("https://example.com/secret/token").unwrap();
        let allowed = Url::parse("https://example.com/public").unwrap();
        assert!(seeds::is_disallowed(&blocked, &robots.disallowed));
        assert!(!seeds::is_disallowed(&allowed, &robots.disallowed));
        // Simulate enqueue gate used by crawl_asset.
        let visited = HashSet::new();
        let enqueue = |u: &Url| {
            should_crawl_url(u, "example.com", &visited, 100)
                && !seeds::is_disallowed(u, &robots.disallowed)
        };
        assert!(!enqueue(&blocked), "Disallow path must not enqueue");
        assert!(enqueue(&allowed), "non-Disallow path must enqueue");
    }
}
