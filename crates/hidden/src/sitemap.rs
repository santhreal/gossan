//! sitemap.xml and robots.txt harvesting for passive endpoint discovery.
//! Finds URLs the site itself advertises — often reveals admin, API, and internal paths.

use gossan_core::Target;
use regex::Regex;
use secfinding::{Evidence, Finding, Severity};
use std::sync::OnceLock;

pub async fn probe(client: &reqwest::Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let base = asset.url.as_str().trim_end_matches('/');
    let mut findings = Vec::new();

    // Try /sitemap.xml and /sitemap_index.xml
    for path in &["/sitemap.xml", "/sitemap_index.xml", "/sitemap.txt"] {
        let url = format!("{}{}", base, path);
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().as_u16() == 200 {
                let body = resp.text().await.unwrap_or_default();
                let urls = extract_sitemap_urls(&body);

                if !urls.is_empty() {
                    // Find any interesting paths (admin, api, internal, etc.)
                    let interesting: Vec<&str> = urls
                        .iter()
                        .filter_map(|u| {
                            let lower = u.to_lowercase();
                            if lower.contains("/admin")
                                || lower.contains("/api/")
                                || lower.contains("/internal")
                                || lower.contains("/private")
                                || lower.contains("/_")
                                || lower.contains("/dashboard")
                                || lower.contains("/console")
                                || lower.contains("/manage")
                            {
                                Some(u.as_str())
                            } else {
                                None
                            }
                        })
                        .take(20)
                        .collect();

                    // Always report: sitemap found with URL count
                    findings.push(
                        crate::finding_builder(
                            target,
                            Severity::Info,
                            format!("sitemap.xml found ({} URLs)", urls.len()),
                            format!(
                                "{} — {} URL{} indexed.",
                                path,
                                urls.len(),
                                if urls.len() == 1 { "" } else { "s" }
                            ),
                        )
                        .evidence(Evidence::HttpResponse {
                            status: 200,
                            headers: vec![],
                            body_excerpt: Some(
                                urls.iter().take(5).cloned().collect::<Vec<_>>().join("\n"),
                            ),
                        })
                        .tag("discovery")
                        .tag("sitemap")
                        .build()
                        .expect("finding builder: required fields are set"),
                    );

                    // Report interesting paths separately
                    if !interesting.is_empty() {
                        findings.push(
                            crate::finding_builder(
                                target,
                                Severity::Low,
                                format!(
                                    "sitemap.xml reveals sensitive paths ({})",
                                    interesting.len()
                                ),
                                format!("sitemap.xml at {} lists internal/admin/API paths.", path),
                            )
                            .evidence(Evidence::HttpResponse {
                                status: 200,
                                headers: vec![],
                                body_excerpt: Some(interesting.join("\n")),
                            })
                            .tag("discovery")
                            .tag("sitemap")
                            .tag("exposure")
                            .build()
                            .expect("finding builder: required fields are set"),
                        );
                    }

                    break; // one sitemap is enough
                }
            }
        }
    }

    Ok(findings)
}

fn extract_sitemap_urls(body: &str) -> Vec<String> {
    static LOC_RE: OnceLock<Regex> = OnceLock::new();
    // Regex pattern is a compile-time constant; construction cannot fail.
    let re = LOC_RE.get_or_init(|| {
        Regex::new(r"<loc>\s*([^\s<>]+)\s*</loc>")
            .unwrap_or_else(|e| panic!("BUG: sitemap regex is invalid: {e}"))
    });

    re.captures_iter(body)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect()
}
