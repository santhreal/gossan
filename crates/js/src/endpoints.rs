//! API endpoint extraction from JavaScript source code.
//!
//! Uses a set of regex patterns to identify string literals that look like
//! API paths (e.g. starting with `/api/`, `/v1/`, etc.) and common
//! AJAX/fetch/axios call patterns.
//!
//! Extracted paths are returned as `Endpoint` structs which can be
//! converted into findings.

use gossan_core::{DiscoverySource, DomainTarget, Target};
use regex::Regex;
use secfinding::{Evidence, FindingBuilder, Severity};
use std::str::FromStr;
use std::sync::OnceLock;
/// `Endpoint`.

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub path: String,
    pub js_url: String,
    pub line: usize,
}

impl Endpoint {
    pub fn into_finding(&self, target: &Target) -> FindingBuilder {
        crate::finding_builder(
            target,
            Severity::Info,
            format!("JS endpoint: {}", self.path),
            "API path extracted from JavaScript — may reveal undocumented endpoints.",
        )
        .evidence(Evidence::JsSnippet {
            url: std::sync::Arc::from(self.js_url.as_str()),
            line: self.line,
            snippet: std::sync::Arc::from(self.path.as_str()),
        })
        .tag("js-endpoint")
    }

    pub fn as_target(&self) -> Option<Target> {
        if self.path.starts_with("http://") || self.path.starts_with("https://") {
            let url = url::Url::parse(&self.path).ok()?;
            let host = url.host_str()?;
            
            // Check if it's an IP
            if let Ok(ip) = std::net::IpAddr::from_str(host) {
                return Some(Target::Host(gossan_core::HostTarget {
                    ip,
                    domain: None,
                }));
            }

            return Some(Target::Domain(DomainTarget {
                domain: host.to_string(),
                source: DiscoverySource::Crawl, // Discovered via JS analysis
            }));
        }
        None
    }
}

struct Pat {
    re: Regex,
    group: usize,
}

fn patterns() -> &'static [Pat] {
    static P: OnceLock<Vec<Pat>> = OnceLock::new();
    P.get_or_init(|| {
        // (pattern, capture group index)
        let specs: &[(&str, usize)] = &[
            // String literal paths starting with API prefixes
            (r#"["'`](/(?:api|v\d+|graphql|rest|rpc|internal|admin|auth|user|account|data|search|webhook|health|metrics|status)[^"'`\s<>{}\[\]]{0,200})["'`]"#, 1),
            // fetch() calls
            (r#"fetch\(["'`]([^"'`\s<>{}\[\]]{1,200})["'`]"#, 1),
            // axios.get/post/etc
            (r#"\.get\(["'`]([^"'`\s<>{}\[\]]{1,200})["'`]"#, 1),
            (r#"\.post\(["'`]([^"'`\s<>{}\[\]]{1,200})["'`]"#, 1),
            (r#"\.put\(["'`]([^"'`\s<>{}\[\]]{1,200})["'`]"#, 1),
            (r#"\.delete\(["'`]([^"'`\s<>{}\[\]]{1,200})["'`]"#, 1),
            // URL constructor
            (r#"new\s+URL\(["'`]([^"'`\s<>{}\[\]]{1,200})["'`]"#, 1),
        ];

        specs
            .iter()
            .filter_map(|(p, g)| {
                match Regex::new(p) {
                    Ok(re) => Some(Pat { re, group: *g }),
                    Err(e) => {
                        tracing::error!("invalid hardcoded JS regex pattern: {e}");
                        None
                    }
                }
            })
            .collect()
    })
}

/// Extract API endpoints from JavaScript content.
pub fn extract(js_url: &str, body: &str) -> Vec<Endpoint> {
    let mut endpoints = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for pat in patterns() {
        for cap in pat.re.captures_iter(body) {
            if let Some(m) = cap.get(pat.group) {
                let path = m.as_str();
                if seen.contains(path) || path.len() < 2 {
                    continue;
                }

                // Determine line number
                let line = body[..m.start()].lines().count();

                endpoints.push(Endpoint {
                    path: path.to_string(),
                    js_url: js_url.to_string(),
                    line,
                });
                seen.insert(path.to_string());
            }
        }
    }

    endpoints
}

