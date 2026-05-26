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

//! Headless browser scanning — screenshot, DOM analysis, SPA detection.
//!
//! Uses `runtime-headless` (Chromium CDP) to render JavaScript-heavy pages and extract
//! security-relevant signals that static HTTP probing cannot see.

use async_trait::async_trait;
use futures::StreamExt;
use gossan_core::{Config, ScanInput, Scanner, Target};
use runtime_headless::chromiumoxide::Browser;
use runtime_headless::{BrowserLaunchOptions, BrowserRuntime};
use secfinding::{Evidence, Finding, FindingBuilder, Severity};
use std::time::Duration;
/// Headless browser scanner — screenshot, DOM analysis, SPA spider, dynamic endpoint discovery.
pub struct HeadlessScanner;

/// Launch options shared by the scanner and its tests (via `runtime-headless`).
#[must_use]
pub fn browser_launch_options() -> BrowserLaunchOptions {
    BrowserLaunchOptions {
        // Preserves pre-migration `BrowserConfig::builder().with_head()` posture.
        headed: true,
        no_sandbox: true,
        ..Default::default()
    }
}

fn finding_builder(
    target: &Target,
    severity: Severity,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> FindingBuilder {
    Finding::builder("headless", target.domain().unwrap_or("?"), severity)
        .title(title)
        .detail(detail)
        .kind(secfinding::FindingKind::InfoDisclosure)
}

#[async_trait]
impl Scanner for HeadlessScanner {
    fn name(&self) -> &'static str {
        "headless"
    }

    fn tags(&self) -> &[&'static str] {
        &["headless", "browser", "dynamic"]
    }

    fn accepts(&self, target: &Target) -> bool {
        matches!(target, Target::Web(_))
    }

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<()> {
        // Drain the inbound target stream into an owned Vec. The
        // ScanInput contract migrated from a buffered `targets: Vec<_>`
        // field to a streaming `target_rx: Mutex<UnboundedReceiver>` —
        // headless was missed in that migration. Pull synchronously
        // here because chromiumoxide's per-tab work needs an owned set
        // upfront to size the buffer_unordered pool.
        let owned: Vec<Target> = {
            let mut rx = input.target_rx.lock().await;
            let mut buf = Vec::new();
            while let Ok(t) = rx.try_recv() {
                buf.push(t);
            }
            buf
        };

        if owned.is_empty() {
            return Ok(());
        }

        let runtime = std::sync::Arc::new(
            BrowserRuntime::launch(&browser_launch_options())
                .await
                .map_err(|e| anyhow::anyhow!("Failed to launch browser: {e}"))?,
        );

        // Parallel execution of all targets using the single browser instance
        let results: Vec<anyhow::Result<(Target, Vec<Finding>)>> = futures::stream::iter(owned)
            .map(|target| {
                let runtime = std::sync::Arc::clone(&runtime);
                let config = config.clone();
                async move { analyze_target(runtime.browser(), target, &config).await }
            })
            // Browser limit for tabs
            .buffer_unordered(config.concurrency.min(10))
            .collect()
            .await;

        for (target, findings) in results.into_iter().flatten() {
            input.emit_target(target);
            for f in findings {
                input.emit(f);
            }
        }

        // `runtime` drops here — BrowserRuntime::Drop aborts the CDP handler task.
        Ok(())
    }
}

async fn analyze_target(
    browser: &Browser,
    mut target: Target,
    config: &Config,
) -> anyhow::Result<(Target, Vec<Finding>)> {
    let Target::Web(ref asset) = target else {
        return Ok((target, vec![]));
    };
    let mut findings = Vec::new();

    let page = browser.new_page(asset.url.as_str()).await?;

    // ── XHR / Fetch Hooking (Legendary Dynamic Discovery) ──────────────────
    // Inject a script to proxy XHR and fetch to catch endpoints that
    // standard event listeners might miss due to race conditions.
    let hook_js = r#"
        (function() {
            window._santh_requests = [];
            
            // Hook Fetch
            const oldFetch = window.fetch;
            window.fetch = function() {
                window._santh_requests.push({ url: arguments[0], type: 'fetch' });
                return oldFetch.apply(this, arguments);
            };

            // Hook XHR
            const oldOpen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function() {
                window._santh_requests.push({ url: arguments[1], type: 'xhr' });
                return oldOpen.apply(this, arguments);
            };
        })();
    "#;
    page.evaluate_on_new_document(hook_js).await.ok();

    // Start event listener early to catch everything from the jump
    let mut request_events = page
        .event_listener::<runtime_headless::chromiumoxide::cdp::browser_protocol::network::EventRequestWillBeSent>()
        .await?;

    let _ = page.goto(asset.url.as_str()).await?;

    // Wait for the initial DOM load
    page.wait_for_navigation().await.ok();

    // ── 1. Authenticated Login (Katana-style) ─────────────────────────────
    if let (Some(user), Some(pass)) = (&config.auth_user, &config.auth_pass) {
        let login_probe = r#"
            (function() {
                const forms = document.forms;
                for (const f of forms) {
                    let hasPassword = false;
                    let userField = null;
                    let passField = null;
                    for (const i of f.elements) {
                        const t = (i.type || '').toLowerCase();
                        if (t === 'password') {
                            hasPassword = true;
                            passField = i;
                        } else if (t === 'text' || t === 'email' || t === 'username') {
                            if (!userField) userField = i;
                        }
                    }
                    if (hasPassword && userField && passField) {
                        userField.setAttribute('data-santh-auth', 'user');
                        passField.setAttribute('data-santh-auth', 'pass');
                        return true;
                    }
                }
                return false;
            })()
        "#;

        if let Ok(res) = page.evaluate(login_probe).await {
            if res.value().and_then(|v| v.as_bool()).unwrap_or(false) {
                if let Ok(user_el) = page.find_element("input[data-santh-auth='user']").await {
                    let _ = user_el.type_str(user).await;
                }
                if let Ok(pass_el) = page.find_element("input[data-santh-auth='pass']").await {
                    let _ = pass_el.type_str(pass).await;
                    let _ = pass_el.press_key("Enter").await;
                }
                // Allow some time for the login to process and session to establish
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
    }

    // ── 2. Stateful Spidering (Clicking all a/button) ─────────────────────
    let click_probe = r#"
        (function() {
            const elements = document.querySelectorAll('a, button');
            const result = [];
            for (let i = 0; i < Math.min(elements.length, 30); i++) {
                const el = elements[i];
                const text = (el.innerText || el.value || '').toLowerCase();
                // Skip destructive actions to avoid losing session or breaking state
                if (text.includes('logout') || text.includes('sign out') || text.includes('delete') || text.includes('remove')) {
                    continue;
                }
                el.setAttribute('data-santh-click', i);
                result.push(i);
            }
            return result;
        })()
    "#;

    if let Ok(res) = page.evaluate(click_probe).await {
        if let Some(idxs) = res.value().and_then(|v| v.as_array()) {
            for idx in idxs {
                if let Some(i) = idx.as_u64() {
                    let selector = format!("[data-santh-click='{}']", i);
                    if let Ok(el) = page.find_element(&selector).await {
                        let _ = el.click().await;
                        // Brief wait for dynamic route changes or background XHRs
                        tokio::time::sleep(Duration::from_millis(400)).await;
                    }
                }
            }
        }
    }

    // Final idle to catch trailing asynchronous requests (React/Vue/Angular)
    tokio::time::sleep(Duration::from_secs(2)).await;

    // ── 3. Evidence Collection ─────────────────────────────────────────────

    // Collect findings from our injected JS hook
    if let Ok(res) = page.evaluate("window._santh_requests").await {
        if let Some(reqs) = res.value().and_then(|v| v.as_array()) {
            for r in reqs {
                let url = r.get("url").and_then(|v| v.as_str()).unwrap_or("");
                let typ = r.get("type").and_then(|v| v.as_str()).unwrap_or("unknown");
                if !url.is_empty() && !url.starts_with("data:") {
                    gossan_core::try_push_finding(
                        finding_builder(
                            &target,
                            Severity::Info,
                            format!("Dynamic {} Endpoint Hooked", typ.to_uppercase()),
                            format!("Injected hook trapped runtime {} request to: {}", typ, url),
                        )
                        .tag("recon")
                        .tag("hooked_request")
                        .evidence(Evidence::raw(url.to_string())),
                        &mut findings,
                    );
                }
            }
        }
    }

    // Drain all trapped network requests from the CDP listener too
    while let Ok(Some(req)) =
        tokio::time::timeout(Duration::from_millis(200), request_events.next()).await
    {
        let url = req.request.url.clone();

        // Filter out obvious noise, trap API paths
        if url.contains("api") || url.ends_with(".json") || url.ends_with(".graphql") {
            gossan_core::try_push_finding(
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
                    body_excerpt: Some(
                        format!(
                            "Method: {}, Headers: {:?}",
                            req.request.method, req.request.headers
                        )
                        .into(),
                    ),
                }),
                &mut findings,
            );
        }
    }

    // ── Global Variable Extraction ──────────────────────────────────────────
    // Look for common sensitive global variables or config objects
    let js_probe = r#"
        (function() {
            const interesting = [];
            const keys = ['config', 'env', 'process', 'API_KEY', 'SECRET', 'TOKEN', 'auth', 'firebase', 'aws'];
            for (const key of Object.keys(window)) {
                if (keys.some(k => key.toLowerCase().includes(k.toLowerCase()))) {
                    try {
                        const val = window[key];
                        if (val && typeof val === 'object') {
                            interesting.push({key, value: JSON.stringify(val).substring(0, 500)});
                        } else if (val) {
                            interesting.push({key, value: String(val).substring(0, 200)});
                        }
                    } catch(e) {}
                }
            }
            return interesting;
        })()
    "#;

    if let Ok(res) = page.evaluate(js_probe).await {
        if let Some(interesting) = res.value().and_then(|v| v.as_array()) {
            for item in interesting {
                let key = item.get("key").and_then(|v| v.as_str()).unwrap_or("?");
                let value = item.get("value").and_then(|v| v.as_str()).unwrap_or("?");

                gossan_core::try_push_finding(finding_builder(
                    &target,
                    Severity::Low,
                    format!("Sensitive JS global detected: {}", key),
                    format!("Found global object/variable `{}` which may contain configuration or credentials.", key),
                )
                .tag("recon")
                .tag("js-global")
                .evidence(Evidence::raw(format!("{}: {}", key, value))), &mut findings);
            }
        }
    }

    // ── Form Extraction ─────────────────────────────────────────────────────
    let form_probe = r#"
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
                    action: f.action,
                    method: f.method || 'GET',
                    inputs: inputs
                });
            }
            return forms;
        })()
    "#;

    let mut discovered_forms = Vec::new();
    if let Ok(res) = page.evaluate(form_probe).await {
        if let Some(forms) = res.value().and_then(|v| v.as_array()) {
            for f in forms {
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
                discovered_forms.push(gossan_core::DiscoveredForm {
                    action,
                    method,
                    inputs,
                });
            }
        }
    }

    page.close().await.ok();

    // Update the asset with discovered forms
    if let Target::Web(ref mut asset) = target {
        asset.forms = discovered_forms;
    }

    Ok((target, findings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::{HostTarget, Protocol, ServiceTarget, WebAssetTarget};
    use url::Url;

    fn web_target() -> Target {
        Target::Web(Box::new(WebAssetTarget {
            url: Url::parse("https://example.com")
                .unwrap_or_else(|_| Url::parse("http://127.0.0.1").unwrap()),
            service: ServiceTarget {
                host: HostTarget {
                    ip: "127.0.0.1"
                        .parse()
                        .unwrap_or_else(|_| "127.0.0.1".parse().unwrap()),
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
    }

    #[test]
    fn scanner_accepts_only_web_targets() {
        let scanner = HeadlessScanner;
        assert!(scanner.accepts(&web_target()));
        assert!(!scanner.accepts(&Target::Host(HostTarget {
            ip: "127.0.0.1"
                .parse()
                .unwrap_or_else(|_| "127.0.0.1".parse().unwrap()),
            domain: None,
        })));
    }

    #[test]
    fn browser_launch_routes_through_runtime_headless() {
        let opts = browser_launch_options();
        assert!(opts.headed);
        assert!(opts.no_sandbox);
        assert_eq!(opts.window_width, BrowserLaunchOptions::default().window_width);
    }

    #[tokio::test]
    #[ignore = "W3-F009: headless Chromium launch >60s; run with cargo test -- --ignored"]
    async fn test_analyze_target_graceful_on_invalid_url() {
        let runtime = match BrowserRuntime::launch(&browser_launch_options()).await {
            Ok(r) => r,
            Err(_) => return,
        };
        let browser = runtime.browser();

        let mut target = web_target();
        if let Target::Web(ref mut asset) = target {
            asset.url = Url::parse("http://0.0.0.0:1").expect("Invalid URL");
        }
        let config = Config::default();

        let result = analyze_target(&browser, target, &config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[ignore = "W3-F009: headless Chromium launch >60s; run with cargo test -- --ignored"]
    async fn test_analyze_target_with_incomplete_auth_does_not_panic() {
        let runtime = match BrowserRuntime::launch(&browser_launch_options()).await {
            Ok(r) => r,
            Err(_) => return,
        };
        let browser = runtime.browser();

        let target = web_target();
        let mut config = Config::default();
        config.auth_user = Some("admin".into());
        config.auth_pass = None; // Should skip login logic

        let _ = analyze_target(&browser, target, &config).await;
    }
}
