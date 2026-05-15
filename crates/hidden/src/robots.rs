//! robots.txt parsing for sensitive path discovery.

use gossan_core::Target;
use secfinding::{Evidence, Finding, Severity};

pub async fn probe(client: &reqwest::Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let url = format!("{}/robots.txt", asset.url.as_str().trim_end_matches('/'));
    let mut findings = Vec::new();

    if let Ok(resp) = client.get(&url).send().await {
        if resp.status().as_u16() == 200 {
            let body = gossan_core::net::bounded_text(resp, 4 * 1024 * 1024).await.unwrap_or_default();

            // Parse robots.txt into groups; extract Sitemap directives and
            // disallow/allow lists that apply to the wildcard User-agent (*).
            fn parse_robots(body: &str) -> (Vec<String>, Vec<String>) {
                struct Group {
                    agents: Vec<String>,
                    allow: Vec<String>,
                    disallow: Vec<String>,
                }

                let mut groups: Vec<Group> = Vec::new();
                let mut current = Group {
                    agents: Vec::new(),
                    allow: Vec::new(),
                    disallow: Vec::new(),
                };
                let mut sitemaps: Vec<String> = Vec::new();

                for raw in body.lines() {
                    let line = raw.split('#').next().unwrap_or("").trim();
                    if line.is_empty() {
                        continue;
                    }
                    if let Some((k, v)) = line.split_once(':') {
                        let key = k.trim().to_lowercase();
                        let val = v.trim().to_string();
                        match key.as_str() {
                            "user-agent" => {
                                // start a new group if the current group already has directives
                                if !current.agents.is_empty() && (!current.allow.is_empty() || !current.disallow.is_empty()) {
                                    groups.push(current);
                                    current = Group { agents: Vec::new(), allow: Vec::new(), disallow: Vec::new() };
                                }
                                current.agents.push(val);
                            }
                            "allow" => current.allow.push(val),
                            "disallow" => current.disallow.push(val),
                            "sitemap" => sitemaps.push(val),
                            _ => {}
                        }
                    }
                }
                // push last group
                if !current.agents.is_empty() || !current.allow.is_empty() || !current.disallow.is_empty() {
                    groups.push(current);
                }

                // Collect disallow rules applicable to the wildcard agent '*'
                let mut wildcard_disallow: Vec<String> = Vec::new();
                for g in groups.iter() {
                    if g.agents.iter().any(|a| a == "*" ) {
                        for d in &g.disallow {
                            if !d.is_empty() && d != "/" {
                                wildcard_disallow.push(d.clone());
                            }
                        }
                    }
                }

                (sitemaps, wildcard_disallow)
            }

            let (sitemaps, disallowed) = parse_robots(&body);

            if !disallowed.is_empty() || !sitemaps.is_empty() {
                // Build human-friendly detail
                let mut detail_parts: Vec<String> = Vec::new();
                if !disallowed.is_empty() {
                    detail_parts.push(format!("{} disallow rules", disallowed.len()));
                }
                if !sitemaps.is_empty() {
                    detail_parts.push(format!("{} sitemap(s)", sitemaps.len()));
                }
                let detail = if detail_parts.is_empty() {
                    "robots.txt parsed but no useful directives found".to_string()
                } else {
                    format!("robots.txt: {} — show sample rules below.", detail_parts.join(", "))
                };

                crate::try_push_finding(
                    crate::file_finding(
                        target,
                        Severity::Info,
                        "robots.txt parsed — directives found",
                        detail,
                    )
                    .evidence(Evidence::HttpResponse {
                        status: 200,
                        headers: vec![],
                        body_excerpt: Some(body.chars().take(500).collect::<String>().into()),
                    })
                    .tag("robots")
                    .tag("recon"),
                    &mut findings,
                );

                // Add a separate finding enumerating disallowed paths when present
                if !disallowed.is_empty() {
                    crate::try_push_finding(
                        crate::file_finding(
                            target,
                            Severity::Low,
                            format!("robots.txt disallow rules ({})", disallowed.len()),
                            format!("Disallow rules (wildcard group '*'): {}", disallowed.join(", ")),
                        )
                        .tag("robots")
                        .tag("recon"),
                        &mut findings,
                    );
                }

                // Add sitemap findings if robots listed sitemaps
                for sm in sitemaps.iter().take(5) {
                    crate::try_push_finding(
                        crate::file_finding(
                            target,
                            Severity::Info,
                            "robots.txt references a sitemap",
                            format!("robots.txt includes Sitemap: {}", sm),
                        )
                        .tag("robots")
                        .tag("sitemap"),
                        &mut findings,
                    );
                }
            }
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    #[test]
    fn disallow_lines_filter_keeps_meaningful_paths() {
        let body = "User-agent: *\nDisallow: /admin\nDisallow: /\nDisallow: /api/private\n";
        let disallowed: Vec<String> = body
            .lines()
            .filter(|l| l.trim_start().to_lowercase().starts_with("disallow:"))
            .filter_map(|l| l.split_once(':').map(|(_, v)| v.trim().to_string()))
            .filter(|p| !p.is_empty() && p != "/")
            .collect();

        assert_eq!(disallowed, vec!["/admin", "/api/private"]);
    }

    #[test]
    fn disallow_lines_are_case_insensitive() {
        let body = "DISALLOW: /secret\nDisAllow: /debug\n";
        let disallowed: Vec<String> = body
            .lines()
            .filter(|l| l.trim_start().to_lowercase().starts_with("disallow:"))
            .filter_map(|l| l.split_once(':').map(|(_, v)| v.trim().to_string()))
            .collect();

        assert_eq!(disallowed, vec!["/secret", "/debug"]);
    }
}
