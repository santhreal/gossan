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
            match key {
                "Allow" => {
                    if let Ok(u) = base_url.join(value) {
                        allowed.push(u);
                    }
                }
                "Disallow" => {
                    if let Ok(u) = base_url.join(value) {
                        disallowed.push(u);
                    }
                }
                "Sitemap" => {
                    if let Ok(u) = Url::parse(value) {
                        sitemaps.push(u);
                    } else if let Ok(u) = base_url.join(value) {
                        sitemaps.push(u);
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
#[derive(Debug, Default)]
pub struct RobotsTxtResult {
    pub allowed: Vec<Url>,
    #[allow(dead_code)]
    pub disallowed: Vec<Url>,
    pub sitemaps: Vec<Url>,
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
            if let Ok(u) = Url::parse(url_str.trim()) {
                urls.push(u);
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
}
