//! sitemap.xml and robots.txt harvesting for passive endpoint discovery.
//! Finds URLs the site itself advertises — often reveals admin, API, and internal paths.

use gossan_core::Target;
use secfinding::{Evidence, Finding, Severity};

/// Maximum recursion depth for sitemapindex entries.
const MAX_SITEMAP_DEPTH: usize = 3;

/// Maximum number of URLs to extract from a single sitemap.
const MAX_URLS_PER_SITEMAP: usize = 10000;

/// Maximum uncompressed size for gzip sitemaps (50 MiB).
const MAX_GZIP_UNCOMPRESSED: usize = 50 * 1024 * 1024;

pub async fn probe(client: &reqwest::Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let base = asset.url.as_str().trim_end_matches('/');
    let mut findings = Vec::new();

    for path in &["/sitemap.xml", "/sitemap_index.xml", "/sitemap.txt"] {
        let url = format!("{}{}", base, path);
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().as_u16() == 200 {
                let urls = extract_sitemap_urls_recursive(client, resp, 0).await;

                if !urls.is_empty() {
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

                    gossan_core::try_push_finding(
                        crate::file_finding(
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
                                urls.iter()
                                    .take(5)
                                    .cloned()
                                    .collect::<Vec<_>>()
                                    .join("\n")
                                    .into(),
                            ),
                        })
                        .tag("discovery")
                        .tag("sitemap"),
                        &mut findings,
                    );

                    if !interesting.is_empty() {
                        gossan_core::try_push_finding(
                            crate::file_finding(
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
                                body_excerpt: Some(interesting.join("\n").into()),
                            })
                            .tag("discovery")
                            .tag("sitemap")
                            .tag("exposure"),
                            &mut findings,
                        );
                    }

                    break;
                }
            }
        }
    }

    Ok(findings)
}

async fn extract_sitemap_urls_recursive(
    client: &reqwest::Client,
    initial_resp: reqwest::Response,
    _depth: usize,
) -> Vec<String> {
    let mut stack: Vec<(Option<String>, reqwest::Response, usize)> = vec![(None, initial_resp, 0)];
    let mut all_urls: Vec<String> = Vec::new();

    while let Some((_, resp, depth)) = stack.pop() {
        if depth > MAX_SITEMAP_DEPTH {
            continue;
        }

        let url = resp.url().clone();

        let content_type: String = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let content_encoding: String = resp
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(_) => continue,
        };

        let body = if content_encoding.eq_ignore_ascii_case("gzip")
            || url.as_str().ends_with(".gz")
            || content_type.contains("gzip")
        {
            match decompress_gzip(&bytes) {
                Ok(s) => s,
                Err(_) => continue,
            }
        } else {
            String::from_utf8_lossy(&bytes).into_owned()
        };

        if body.contains("<sitemapindex") {
            let nested_urls = extract_loc_urls(&body);
            for nested_url in nested_urls.into_iter().rev() {
                if let Ok(resp) = client.get(&nested_url).send().await {
                    if resp.status().as_u16() == 200 {
                        stack.push((Some(nested_url), resp, depth + 1));
                    }
                }
            }
        } else {
            let urls = extract_loc_urls(&body);
            all_urls.extend(urls);
            if all_urls.len() >= MAX_URLS_PER_SITEMAP {
                all_urls.truncate(MAX_URLS_PER_SITEMAP);
                break;
            }
        }
    }

    all_urls
}

fn extract_loc_urls(body: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let mut remaining = body;

    while let Some(start_idx) = remaining.find("<loc>") {
        let after_open = &remaining[start_idx + 5..];

        if let Some(end_idx) = after_open.find("</loc>") {
            let url_content = &after_open[..end_idx];
            let url = url_content.trim();

            if !url.is_empty() && url.starts_with("http") {
                urls.push(url.to_string());
            }

            remaining = &after_open[end_idx + 6..];
        } else {
            break;
        }

        if urls.len() >= MAX_URLS_PER_SITEMAP {
            break;
        }
    }

    urls
}

fn decompress_gzip(bytes: &[u8]) -> Result<String, anyhow::Error> {
    if bytes.len() < 2 || bytes[0] != 0x1f || bytes[1] != 0x8b {
        return Ok(String::from_utf8_lossy(bytes).into_owned());
    }

    use flate2::read::GzDecoder;
    use std::io::Read;

    let mut decoder = GzDecoder::new(bytes);
    let mut buf = Vec::new();
    let mut total = 0usize;
    let mut chunk = [0u8; 8192];

    loop {
        let n = decoder.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        total += n;
        if total > MAX_GZIP_UNCOMPRESSED {
            return Err(anyhow::anyhow!(
                "gzip payload exceeds {} bytes — possible gzip bomb",
                MAX_GZIP_UNCOMPRESSED
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_loc_urls_basic() {
        let xml = r#"<?xml version="1.0"?>
<urlset>
    <url>
        <loc>https://example.com/page1</loc>
        <lastmod>2024-01-01</lastmod>
    </url>
    <url>
        <loc>https://example.com/page2</loc>
    </url>
</urlset>"#;
        let urls = extract_loc_urls(xml);
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0], "https://example.com/page1");
        assert_eq!(urls[1], "https://example.com/page2");
    }

    #[test]
    fn extract_loc_urls_with_whitespace() {
        let xml = r#"<urlset>
    <loc>
        https://example.com/page1
    </loc>
</urlset>"#;
        let urls = extract_loc_urls(xml);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0], "https://example.com/page1");
    }

    #[test]
    fn extract_loc_urls_empty() {
        let xml = r#"<urlset></urlset>"#;
        let urls = extract_loc_urls(xml);
        assert!(urls.is_empty());
    }

    #[test]
    fn extract_loc_urls_malformed_no_closing_tag() {
        let xml = r#"<urlset><loc>https://example.com/page1"#;
        let urls = extract_loc_urls(xml);
        assert!(urls.is_empty());
    }

    #[test]
    fn extract_loc_urls_skips_non_http() {
        let xml = r#"<urlset>
    <loc>/relative/path</loc>
    <loc>https://example.com/page1</loc>
</urlset>"#;
        let urls = extract_loc_urls(xml);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0], "https://example.com/page1");
    }

    #[test]
    fn extract_loc_urls_sitemapindex() {
        let xml = r#"<?xml version="1.0"?>
<sitemapindex>
    <sitemap>
        <loc>https://example.com/sitemap1.xml</loc>
    </sitemap>
    <sitemap>
        <loc>https://example.com/sitemap2.xml.gz</loc>
    </sitemap>
</sitemapindex>"#;
        let urls = extract_loc_urls(xml);
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0], "https://example.com/sitemap1.xml");
        assert_eq!(urls[1], "https://example.com/sitemap2.xml.gz");
    }

    #[test]
    fn extract_loc_urls_respects_max_limit() {
        let mut xml = String::from("<urlset>");
        for i in 0..MAX_URLS_PER_SITEMAP + 100 {
            xml.push_str(&format!("<loc>https://example.com/page{}</loc>", i));
        }
        xml.push_str("</urlset>");

        let urls = extract_loc_urls(&xml);
        assert_eq!(urls.len(), MAX_URLS_PER_SITEMAP);
    }

    #[test]
    fn decompress_gzip_rejects_invalid() {
        let result = decompress_gzip(b"not gzip");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "not gzip");
    }
}
