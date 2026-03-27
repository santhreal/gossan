//! Authenticated web crawler — form extraction, parameter discovery, link following.
//!
//! This scanner takes `WebAssetTarget` inputs and crawls each one:
//! 1. Follows `<a href>` links with optional authentication cookies
//! 2. Extracts `<form>` elements with their inputs (action, method, fields)
//! 3. Discovers URL query parameters from crawled pages
//! 4. Enriches each discovered `WebAssetTarget` with forms and parameters
//!
//! The output is a set of enriched `WebAssetTarget` values ready for
//! downstream vulnerability scanning (Karyx routing, Calyx templates, etc.).

extern crate self as reqwest;
pub use stealthreq::http::{Client, Method, Proxy, Request, Response, StatusCode, Url};
pub use stealthreq::http::{header, redirect};

mod extract;

use std::collections::HashSet;

use async_trait::async_trait;
use gossan_core::{
    build_client, Config, DiscoveredForm, DiscoveredParam, ParamLocation, ParamSource, ScanInput,
    ScanOutput, Scanner, Target, WebAssetTarget,
};

/// Authenticated web crawler that discovers forms and parameters.
pub struct CrawlScanner;

#[async_trait]
impl Scanner for CrawlScanner {
    fn name(&self) -> &'static str {
        "crawl"
    }
    fn tags(&self) -> &[&'static str] {
        &["active", "web", "crawl"]
    }
    fn accepts(&self, target: &Target) -> bool {
        matches!(target, Target::Web(_))
    }

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<ScanOutput> {
        let mut out = ScanOutput::empty();
        let client = build_client(config, true)?;

        let web_assets: Vec<WebAssetTarget> = input
            .targets
            .iter()
            .filter_map(|t| {
                if let Target::Web(w) = t {
                    Some(*w.clone())
                } else {
                    None
                }
            })
            .collect();

        for asset in web_assets {
            match crawl_asset(&client, &asset, config).await {
                Ok(enriched_targets) => {
                    for target in enriched_targets {
                        input.emit_target(Target::Web(Box::new(target.clone())));
                        out.targets.push(Target::Web(Box::new(target)));
                    }
                }
                Err(e) => {
                    tracing::warn!(url = %asset.url, err = %e, "crawl failed for asset");
                }
            }
        }

        Ok(out)
    }
}

async fn crawl_asset(
    client: &reqwest::Client,
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

        let resp = match client.get(url.as_str()).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };

        if !resp.status().is_success() {
            continue;
        }

        let body = match resp.text().await {
            Ok(b) => b,
            Err(_) => continue,
        };

        // Extract forms from this page
        for form in extract::extract_forms(&body, &url) {
            if !all_forms
                .iter()
                .any(|f| f.action == form.action && f.method == form.method)
            {
                // Add form inputs as discovered parameters
                for (name, _input_type) in &form.inputs {
                    if !all_params.iter().any(|p| p.name == *name) {
                        all_params.push(DiscoveredParam {
                            name: name.clone(),
                            location: if form.method.eq_ignore_ascii_case("POST") {
                                ParamLocation::Body
                            } else {
                                ParamLocation::Query
                            },
                            source: ParamSource::HtmlForm,
                        });
                    }
                }
                all_forms.push(form);
            }
        }

        // Extract URL parameters from this page's URL
        for (name, _value) in url.query_pairs() {
            let name = name.to_string();
            if !all_params.iter().any(|p| p.name == name) {
                all_params.push(DiscoveredParam {
                    name,
                    location: ParamLocation::Query,
                    source: ParamSource::UrlObserved,
                });
            }
        }

        // Follow links if within depth limit
        if depth < max_depth {
            for link in extract::extract_links(&body, &url) {
                if link.host_str() == Some(&base_host) && !visited.contains(link.as_str()) {
                    discovered_urls.push(link.clone());
                    queue.push((link, depth + 1));
                }
            }
        }
    }

    tracing::info!(
        seed = %seed.url,
        pages = visited.len(),
        forms = all_forms.len(),
        params = all_params.len(),
        links = discovered_urls.len(),
        "crawl complete"
    );

    // Build enriched WebAssetTargets for each discovered URL
    let mut results = Vec::new();

    // Enrich the seed asset with forms/params
    let mut enriched_seed = seed.clone();
    enriched_seed.forms = all_forms;
    enriched_seed.params = all_params;
    results.push(enriched_seed);

    // Create new WebAssetTargets for discovered URLs (without forms/params — those
    // belong to the page they were found on, not the linked page)
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

#[cfg(test)]
mod tests {
    use super::extract;
    use super::CrawlScanner;
    use gossan_core::{
        CrawlConfig, HostTarget, Protocol, Scanner, ServiceTarget, Target, WebAssetTarget,
    };

    #[test]
    fn extract_forms_basic() {
        let html = r#"
            <form action="/login" method="POST">
                <input name="username" type="text">
                <input name="password" type="password">
                <button type="submit">Login</button>
            </form>
        "#;
        let base = url::Url::parse("https://example.com/page").unwrap();
        let forms = extract::extract_forms(html, &base);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].action, "https://example.com/login");
        assert_eq!(forms[0].method, "POST");
        assert_eq!(forms[0].inputs.len(), 2);
    }

    #[test]
    fn extract_links_filters_external() {
        let html = r#"
            <a href="/about">About</a>
            <a href="https://example.com/contact">Contact</a>
            <a href="https://evil.com/steal">Evil</a>
        "#;
        let base = url::Url::parse("https://example.com/").unwrap();
        let links = extract::extract_links(html, &base);
        // Should include /about and /contact but not evil.com
        assert!(links.iter().any(|l| l.path() == "/about"));
        assert!(links.iter().any(|l| l.path() == "/contact"));
        assert!(!links.iter().any(|l| l.host_str() == Some("evil.com")));
    }

    #[test]
    fn extract_forms_relative_action() {
        let html = r#"<form action="search" method="GET"><input name="q" type="text"></form>"#;
        let base = url::Url::parse("https://example.com/app/").unwrap();
        let forms = extract::extract_forms(html, &base);
        assert_eq!(forms[0].action, "https://example.com/app/search");
    }

    #[test]
    fn scanner_accepts_web_targets() {
        let scanner = CrawlScanner;
        let target = Target::Web(Box::new(WebAssetTarget {
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
        }));
        assert!(scanner.accepts(&target));
    }

    const _: () = {
        let d = CrawlConfig {
            max_pages: 50,
            max_depth: 3,
        };
        assert!(d.max_pages > 0);
        assert!(d.max_depth > 0);
    };
}
