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
            let body = resp.text().await.unwrap_or_default();
            let disallowed: Vec<String> = body
                .lines()
                .filter(|l| l.trim_start().to_lowercase().starts_with("disallow:"))
                .filter_map(|l| l.split_once(':').map(|(_, v)| v.trim().to_string()))
                .filter(|p| !p.is_empty() && p != "/")
                .collect();

            if !disallowed.is_empty() {
                findings.push(
                    crate::finding_builder(
                        target,
                        Severity::Info,
                        "robots.txt reveals hidden paths",
                        format!(
                            "{} disallowed paths found — hints at sensitive areas: {}",
                            disallowed.len(),
                            disallowed.join(", ")
                        ),
                    )
                    .evidence(Evidence::HttpResponse {
                        status: 200,
                        headers: vec![],
                        body_excerpt: Some(body.chars().take(500).collect()),
                    })
                    .tag("robots")
                    .tag("recon")
                    .build()
                    .expect("finding builder: required fields are set"),
                );
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
