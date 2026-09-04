//! Seed URL discovery from robots.txt and sitemap.xml.
//!
//! Katana and other advanced crawlers use these discovery files to bootstrap
//! the crawl with URLs that might not be linked from the seed page.

use url::Url;

/// Parse a robots.txt body and return all Allow/Disallow/Sitemap lines.
/// We treat `Allow` paths as potential crawl targets and `Sitemap` URLs
/// as direct seeds. Disallowed paths are returned for information but
/// typically skipped during crawling.
pub fn parse_robots_txt(body: &str, base_url: &Url) -> RobotsTxtResult {
    let mut allowed = Vec::new();
    let mut disallowed = Vec::new();
    let mut sitemaps = Vec::new();

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            match key.to_lowercase().as_str() {
                "allow" => {
                    if let Ok(u) = base_url.join(value) {
                        allowed.push(u);
                    }
                }
                "disallow" => {
                    // Empty Disallow value means "allow all" (RFC 9309 §2.2.2).
                    // Skip it so it does not block every path on the site.
                    if !value.is_empty() {
                        if let Ok(u) = base_url.join(value) {
                            disallowed.push(u);
                        }
                    }
                }
                "sitemap" => {
                    if let Ok(u) = Url::parse(value) {
                        if u.scheme() == "http" || u.scheme() == "https" {
                            sitemaps.push(u);
                        }
                    } else if let Ok(u) = base_url.join(value) {
                        if u.scheme() == "http" || u.scheme() == "https" {
                            sitemaps.push(u);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    RobotsTxtResult {
        allowed,
        disallowed,
        sitemaps,
    }
}

/// Result of parsing robots.txt.
///
/// `crawl_asset` fetches `/robots.txt` at crawl start and filters queue
/// candidates with [`is_disallowed`] so Disallow paths are not visited.
#[derive(Debug, Default)]
pub struct RobotsTxtResult {
    pub allowed: Vec<Url>,
    /// Paths the site asks crawlers not to visit. Honored by the crawl queue.
    pub disallowed: Vec<Url>,
    pub sitemaps: Vec<Url>,
}

/// True when `url`'s path is covered by a robots.txt Disallow prefix.
///
/// Empty Disallow values are ignored (they mean "allow all" in robots.txt).
/// Matching is the standard robots prefix match (`/admin` blocks `/admin/x`
/// and also `/administration`).
pub fn is_disallowed(url: &Url, disallowed: &[Url]) -> bool {
    let path = url.path();
    disallowed.iter().any(|d| {
        let dp = d.path();
        !dp.is_empty() && path.starts_with(dp)
    })
}

/// Decode common XML entities in a string without double-decoding.
fn decode_xml_entities(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '&' {
            let mut entity = String::new();
            let mut has_semicolon = false;
            while let Some(&next) = chars.peek() {
                if next == ';' {
                    chars.next();
                    has_semicolon = true;
                    break;
                }
                entity.push(next);
                chars.next();
            }
            match entity.as_str() {
                "amp" if has_semicolon => result.push('&'),
                "lt" if has_semicolon => result.push('<'),
                "gt" if has_semicolon => result.push('>'),
                "quot" if has_semicolon => result.push('"'),
                "apos" if has_semicolon => result.push('\''),
                _ => {
                    result.push('&');
                    result.push_str(&entity);
                    if has_semicolon {
                        result.push(';');
                    }
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Parse a sitemap XML body and extract all `<loc>` URLs.
pub fn parse_sitemap(body: &str) -> Vec<Url> {
    let mut urls = Vec::new();
    // Simple regex-free parsing: look for `<loc>` tags
    let mut rest = body;
    while let Some(start) = rest.find("<loc>") {
        let after_start = &rest[start + 5..];
        if let Some(end) = after_start.find("</loc>") {
            let url_str = &after_start[..end];
            // If this <loc> contains another <loc> before its </loc>,
            // it is malformed; skip to the next <loc> and continue.
            if let Some(nested_loc) = url_str.find("<loc>") {
                rest = &after_start[nested_loc..];
                continue;
            }
            let decoded = decode_xml_entities(url_str.trim());
            if let Ok(u) = Url::parse(&decoded) {
                if u.scheme() == "http" || u.scheme() == "https" {
                    urls.push(u);
                }
            }
            rest = &after_start[end + 6..];
        } else {
            break;
        }
    }
    urls
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn robots_parses_allow_disallow_sitemap() {
        let body = r#"
User-agent: *
Disallow: /admin
Allow: /public
Sitemap: https://example.com/sitemap.xml
"#;
        let base = Url::parse("https://example.com").unwrap();
        let res = parse_robots_txt(body, &base);
        assert_eq!(res.allowed.len(), 1);
        assert_eq!(res.allowed[0].path(), "/public");
        assert_eq!(res.disallowed.len(), 1);
        assert_eq!(res.disallowed[0].path(), "/admin");
        assert_eq!(res.sitemaps.len(), 1);
        assert_eq!(res.sitemaps[0].as_str(), "https://example.com/sitemap.xml");
    }

    #[test]
    fn sitemap_extracts_urls() {
        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset>
  <url>
    <loc>https://example.com/page1</loc>
  </url>
  <url>
    <loc>https://example.com/page2</loc>
  </url>
</urlset>"#;
        let urls = parse_sitemap(body);
        assert_eq!(urls.len(), 2);
        assert!(urls.iter().any(|u| u.path() == "/page1"));
        assert!(urls.iter().any(|u| u.path() == "/page2"));
    }

    // ── Adversarial / edge-case tests ─────────────────────────────────────

    #[test]
    fn robots_rejects_non_http_sitemaps() {
        let body = r#"
Sitemap: ftp://example.com/sitemap.xml
Sitemap: javascript:alert(1)
Sitemap: https://example.com/sitemap.xml
"#;
        let base = Url::parse("https://example.com").unwrap();
        let res = parse_robots_txt(body, &base);
        assert_eq!(res.sitemaps.len(), 1);
        assert_eq!(res.sitemaps[0].as_str(), "https://example.com/sitemap.xml");
    }

    #[test]
    fn decode_xml_entities_no_double_decode() {
        assert_eq!(decode_xml_entities("&amp;lt;"), "&lt;");
        assert_eq!(decode_xml_entities("&amp;amp;"), "&amp;");
        assert_eq!(decode_xml_entities("&lt;amp;"), "<amp;");
    }

    #[test]
    fn decode_xml_entities_standard() {
        let raw = "&amp; &lt; &gt; &quot; &apos;";
        assert_eq!(decode_xml_entities(raw), "& < > \" '");
    }

    #[test]
    fn decode_xml_entities_unknown_unchanged() {
        assert_eq!(decode_xml_entities("&foo;"), "&foo;");
    }

    #[test]
    fn sitemap_skips_malformed_nested_loc() {
        let body = r#"<loc><loc>http://example.com</loc></loc>"#;
        let urls = parse_sitemap(body);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].as_str(), "http://example.com/");
    }

    #[test]
    fn sitemap_skips_non_http_urls() {
        let body = r#"<loc>ftp://example.com/file</loc><loc>https://example.com/page</loc>"#;
        let urls = parse_sitemap(body);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].as_str(), "https://example.com/page");
    }

    #[test]
    fn sitemap_empty_body() {
        assert!(parse_sitemap("").is_empty());
    }

    #[test]
    fn sitemap_unclosed_loc() {
        let body = r#"<loc>http://example.com/page"#;
        assert!(parse_sitemap(body).is_empty());
    }

    #[test]
    fn sitemap_decodes_xml_entities_in_url() {
        let body = r#"<loc>https://example.com/page?a=1&amp;b=2</loc>"#;
        let urls = parse_sitemap(body);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].as_str(), "https://example.com/page?a=1&b=2");
    }

    #[test]
    fn is_disallowed_honors_prefix_match() {
        let base = Url::parse("https://example.com").unwrap();
        let body = "User-agent: *\nDisallow: /private\nDisallow: /admin\n";
        let res = parse_robots_txt(body, &base);
        assert!(is_disallowed(
            &Url::parse("https://example.com/private/secret").unwrap(),
            &res.disallowed
        ));
        assert!(is_disallowed(
            &Url::parse("https://example.com/admin").unwrap(),
            &res.disallowed
        ));
        assert!(
            !is_disallowed(
                &Url::parse("https://example.com/public").unwrap(),
                &res.disallowed
            ),
            "non-disallowed path must remain crawlable"
        );
    }

    #[test]
    fn is_disallowed_ignores_empty_disallow_rule() {
        let base = Url::parse("https://example.com").unwrap();
        // Empty Disallow means allow all for that rule.
        let body = "User-agent: *\nDisallow:\n";
        let res = parse_robots_txt(body, &base);
        assert!(
            !is_disallowed(&Url::parse("https://example.com/anything").unwrap(), &res.disallowed),
            "empty Disallow must not block paths"
        );
    }

    // ── proptest property tests ───────────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn parse_robots_txt_never_panics(body in "\\PC{0,4096}") {
            let base = Url::parse("https://example.com").unwrap();
            let _ = parse_robots_txt(&body, &base);
        }

        #[test]
        fn parse_sitemap_never_panics(body in "\\PC{0,4096}") {
            let _ = parse_sitemap(&body);
        }

        #[test]
        fn parse_sitemap_returns_only_http_or_https(body in "\\PC{0,4096}") {
            for url in parse_sitemap(&body) {
                prop_assert!(
                    url.scheme() == "http" || url.scheme() == "https",
                    "non-HTTP URL leaked through: {}",
                    url
                );
            }
        }

        #[test]
        fn decode_xml_entities_never_panics(s in "\\PC{0,4096}") {
            let _ = decode_xml_entities(&s);
        }

        #[test]
        fn decode_xml_entities_idempotent_for_plaintext(s in "[^&<>'\"]{0,256}") {
            // Text without entities should be unchanged.
            prop_assert_eq!(decode_xml_entities(&s), s);
        }
    }
}
