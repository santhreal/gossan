//! sitemap.xml and robots.txt harvesting for passive endpoint discovery.
//! Finds URLs the site itself advertises (often reveals admin, API, and internal paths).

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
        match client.get(&url).send().await {
            Ok(resp) => {
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
                                "{}: {} URL{} indexed.",
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
            Err(e) => {
                tracing::warn!("sitemap probe send failed: url={} error={}", url, e);
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

        // Cap the *compressed* read at MAX_GZIP_UNCOMPRESSED, gzip
        // expansion is bounded separately by `decompress_gzip`. A
        // hostile sitemap server streaming gigabytes would otherwise
        // OOM the scanner before the parser ever sees the data.
        let bytes = match crate::soft404::read_limited(resp, MAX_GZIP_UNCOMPRESSED).await {
            Some(b) => b,
            None => {
                tracing::warn!("sitemap body read failed or oversized; skipping: url={}", url);
                continue;
            }
        };

        let body = if content_encoding.eq_ignore_ascii_case("gzip")
            || url.as_str().ends_with(".gz")
            || content_type.contains("gzip")
        {
            match decompress_gzip(&bytes) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("sitemap gzip decompress failed; skipping: url={} error={}", url, e);
                    continue;
                }
            }
        } else {
            String::from_utf8_lossy(&bytes).into_owned()
        };

        if body.contains("<sitemapindex") {
            let nested_urls = extract_loc_urls(&body);
            for nested_url in nested_urls.into_iter().rev() {
                match client.get(&nested_url).send().await {
                    Ok(resp) => {
                        if resp.status().as_u16() == 200 {
                            stack.push((Some(nested_url), resp, depth + 1));
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "sitemap nested send failed: url={} error={}",
                            nested_url, e
                        );
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
    // ASCII tag match on a lowered view; slice the original body by the same offsets.
    let lower = body.to_ascii_lowercase();
    let mut cursor = 0usize;

    while let Some(rel) = lower[cursor..].find("<loc>") {
        let open_at = cursor + rel;
        let after_open = open_at + 5;
        let Some(end_rel) = lower[after_open..].find("</loc>") else {
            break;
        };
        let close_at = after_open + end_rel;
        let url_content = &body[after_open..close_at];
        let url = gossan_core::xml_unescape(url_content.trim());

        if !url.is_empty() && url.starts_with("http") {
            urls.push(url);
        }

        cursor = close_at + 6;
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
                "gzip payload exceeds {} bytes, possible gzip bomb",
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

    #[test]
    fn extract_loc_urls_preserves_query_strings() {
        let xml = "<urlset><loc>https://example.com/page?id=1</loc></urlset>";
        let urls = extract_loc_urls(xml);
        assert_eq!(urls, vec!["https://example.com/page?id=1"]);
    }

    #[test]
    fn extract_loc_urls_skips_ftp_urls() {
        let xml = "<urlset><loc>ftp://example.com/file</loc><loc>https://example.com/page</loc></urlset>";
        let urls = extract_loc_urls(xml);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0], "https://example.com/page");
    }

    #[test]
    fn extract_loc_urls_handles_port_numbers() {
        let xml = "<urlset><loc>https://example.com:8080/page</loc></urlset>";
        let urls = extract_loc_urls(xml);
        assert_eq!(urls, vec!["https://example.com:8080/page"]);
    }

    #[test]
    fn extract_loc_urls_preserves_subdomains() {
        let xml = "<urlset><loc>https://api.example.com/v1</loc></urlset>";
        let urls = extract_loc_urls(xml);
        assert_eq!(urls, vec!["https://api.example.com/v1"]);
    }

    #[test]
    fn extract_loc_urls_ignores_empty_after_trim() {
        let xml = "<urlset><loc>   </loc><loc>https://example.com/</loc></urlset>";
        let urls = extract_loc_urls(xml);
        assert_eq!(urls.len(), 1);
    }

    #[test]
    fn extract_loc_urls_handles_nested_loc() {
        let xml = "<urlset><url><loc>https://example.com/nested</loc></url></urlset>";
        let urls = extract_loc_urls(xml);
        assert_eq!(urls, vec!["https://example.com/nested"]);
    }

    #[test]
    fn extract_loc_urls_skips_empty_urlset() {
        let xml = "<urlset></urlset>";
        let urls = extract_loc_urls(xml);
        assert!(urls.is_empty());
    }

    #[test]
    fn extract_loc_urls_preserves_http() {
        let xml = "<urlset><loc>http://example.com/page</loc></urlset>";
        let urls = extract_loc_urls(xml);
        assert_eq!(urls[0], "http://example.com/page");
    }

    #[test]
    fn extract_loc_urls_handles_large_xml() {
        let mut xml = String::from("<urlset>");
        for i in 0..100 {
            xml.push_str(&format!("<loc>https://example.com/page{}</loc>", i));
        }
        xml.push_str("</urlset>");
        let urls = extract_loc_urls(&xml);
        assert_eq!(urls.len(), 100);
    }

    #[test]
    fn extract_loc_urls_empty_string_adversarial() {
        let urls = extract_loc_urls("");
        assert!(urls.is_empty());
    }

    #[test]
    fn extract_loc_urls_no_loc_tags_adversarial() {
        let xml = "<urlset><url></url></urlset>";
        let urls = extract_loc_urls(xml);
        assert!(urls.is_empty());
    }

    #[test]
    fn extract_loc_urls_malformed_unclosed_loc_adversarial() {
        let xml = "<urlset><loc>https://example.com/page1</loc><loc>https://example.com/page2";
        let urls = extract_loc_urls(xml);
        assert_eq!(urls.len(), 1);
    }

    #[test]
    fn extract_loc_urls_multiple_urlsets_adversarial() {
        let xml = "<urlset><loc>https://a.com</loc></urlset><urlset><loc>https://b.com</loc></urlset>";
        let urls = extract_loc_urls(xml);
        assert_eq!(urls.len(), 2);
    }

    #[test]
    fn extract_loc_urls_ignores_javascript_urls_adversarial() {
        let xml = "<urlset><loc>javascript:alert(1)</loc><loc>https://example.com/</loc></urlset>";
        let urls = extract_loc_urls(xml);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0], "https://example.com/");
    }

    #[test]
    fn extract_loc_urls_ignores_mailto_urls_adversarial() {
        let xml = "<urlset><loc>mailto:test@example.com</loc><loc>https://example.com/</loc></urlset>";
        let urls = extract_loc_urls(xml);
        assert_eq!(urls.len(), 1);
    }

    #[test]
    fn extract_loc_urls_preserves_https_with_port_adversarial() {
        let xml = "<urlset><loc>https://example.com:8443/path</loc></urlset>";
        let urls = extract_loc_urls(xml);
        assert_eq!(urls, vec!["https://example.com:8443/path"]);
    }

    #[test]
    fn decompress_gzip_not_gzip_returns_as_string_adversarial() {
        let result = decompress_gzip(b"not gzip at all");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "not gzip at all");
    }

    #[test]
    fn decompress_gzip_valid_gzip_adversarial() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"hello sitemap").unwrap();
        let compressed = encoder.finish().unwrap();
        let result = decompress_gzip(&compressed);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "hello sitemap");
    }

    #[test]
    fn decompress_gzip_binary_non_utf8_adversarial() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&[0x00, 0x01, 0x02, 0x03]).unwrap();
        let compressed = encoder.finish().unwrap();
        let result = decompress_gzip(&compressed);
        assert!(result.is_ok());
    }

    /// Adversarial: uppercase/mixed-case <LOC> tags must still extract URLs.
    #[test]
    fn extract_loc_urls_case_insensitive_loc_adversarial() {
        let xml = r#"<?xml version="1.0"?>
<urlset>
  <url>
    <LOC>https://example.com/Upper</LOC>
  </url>
  <url>
    <Loc>https://example.com/Mixed</Loc>
  </url>
  <url>
    <loc>https://example.com/lower</loc>
  </url>
</urlset>"#;
        let urls = extract_loc_urls(xml);
        assert_eq!(
            urls,
            vec![
                "https://example.com/Upper",
                "https://example.com/Mixed",
                "https://example.com/lower",
            ]
        );
    }

    /// Adversarial: XML entities inside <loc> must be decoded before the
    /// URLs are used for further requests.
    #[test]
    fn extract_loc_urls_decodes_xml_entities() {
        let xml = "<urlset><loc>https://example.com/page?a=1&amp;b=2</loc></urlset>";
        let urls = extract_loc_urls(xml);
        assert_eq!(urls, vec!["https://example.com/page?a=1&b=2"]);
    }

    #[test]
    fn extract_loc_urls_decodes_multiple_xml_entities() {
        let xml = "<urlset><loc>https://example.com/path?x=&lt;1&gt;&amp;y=2</loc></urlset>";
        let urls = extract_loc_urls(xml);
        assert_eq!(urls, vec!["https://example.com/path?x=<1>&y=2"]);
    }
    #[test]
    fn extract_loc_urls_malformed_nested() {
        let xml = "<urlset><loc><loc>https://a.com</loc></loc></urlset>";
        let urls = extract_loc_urls(xml);
        // The first <loc> contains <loc>https://a.com, so the inner URL is skipped
        // because it doesn't start with 'http' (starts with <loc>).
        // The second </loc> closes the first, leaving empty content.
        // Result: zero URLs, but must not panic.
        assert_eq!(urls.len(), 0);
    }

    /// Adversarial: extreme number of <loc> tags must be capped.
    #[test]
    fn extract_loc_urls_extreme_count_respects_cap() {
        let mut xml = String::from("<urlset>");
        for i in 0..MAX_URLS_PER_SITEMAP + 500 {
            xml.push_str(&format!("<loc>https://example.com/page{}</loc>", i));
        }
        xml.push_str("</urlset>");
        let urls = extract_loc_urls(&xml);
        assert_eq!(urls.len(), MAX_URLS_PER_SITEMAP);
    }

    /// Adversarial: empty and whitespace-only URLs must be skipped.
    #[test]
    fn extract_loc_urls_skips_empty_and_whitespace() {
        let xml = "<urlset><loc>   </loc><loc>https://example.com/</loc><loc>\t\n</loc></urlset>";
        let urls = extract_loc_urls(xml);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0], "https://example.com/");
    }

    /// Property tests for sitemap URL extraction.
    #[cfg(test)]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn prop_extract_loc_urls_never_panics(xml in "\\PC*") {
                let _ = extract_loc_urls(&xml);
            }

            #[test]
            fn prop_extract_loc_urls_count_bounded(
                n in 0usize..(MAX_URLS_PER_SITEMAP + 20)
            ) {
                let mut xml = String::from("<urlset>");
                for i in 0..n {
                    xml.push_str(&format!("<loc>https://example.com/{}</loc>", i));
                }
                xml.push_str("</urlset>");
                let urls = extract_loc_urls(&xml);
                prop_assert!(urls.len() <= MAX_URLS_PER_SITEMAP);
                prop_assert!(urls.len() <= n);
            }

            #[test]
            fn prop_decompress_gzip_never_panics(data in proptest::collection::vec(any::<u8>(), 0..256)) {
                let _ = decompress_gzip(&data);
            }
        }
    }
}
