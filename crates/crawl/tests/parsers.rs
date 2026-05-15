//! Coverage for `gossan_crawl` pure-CPU parsers — robots.txt + sitemap.xml.
//!
//! Boosts crawl test coverage past the audit's 3-test floor and locks
//! down the parsers' edge-case behaviour (User-agent matching,
//! Disallow normalisation, sitemap URL extraction, malformed input).

use gossan_crawl::seeds::{parse_robots_txt, parse_sitemap, RobotsTxtResult};
use url::Url;

fn base() -> Url {
    Url::parse("https://example.com/").unwrap()
}

#[test]
fn parse_robots_txt_extracts_disallow_paths() {
    let body = "\
User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /public/
Sitemap: https://example.com/sitemap.xml
";
    let r = parse_robots_txt(body, &base());
    assert!(r.disallowed.iter().any(|u| u.path() == "/admin/"));
    assert!(r.disallowed.iter().any(|u| u.path() == "/private/"));
    assert!(r
        .sitemaps
        .iter()
        .any(|u| u.as_str().contains("sitemap.xml")));
}

#[test]
fn parse_robots_txt_handles_empty_body() {
    let r = parse_robots_txt("", &base());
    assert!(r.disallowed.is_empty());
    assert!(r.sitemaps.is_empty());
}

#[test]
fn parse_robots_txt_ignores_comment_lines() {
    let body = "\
# this is a comment
User-agent: *
# another
Disallow: /secret/
";
    let r = parse_robots_txt(body, &base());
    assert_eq!(r.disallowed.len(), 1);
    assert_eq!(r.disallowed[0].path(), "/secret/");
}

#[test]
fn parse_sitemap_extracts_loc_urls() {
    let xml = r#"<?xml version="1.0"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/a</loc></url>
  <url><loc>https://example.com/b</loc></url>
  <url><loc>https://example.com/c</loc></url>
</urlset>
"#;
    let urls = parse_sitemap(xml);
    assert_eq!(urls.len(), 3);
    assert!(urls.iter().any(|u| u.path() == "/a"));
}

#[test]
fn parse_sitemap_returns_empty_on_malformed_xml() {
    let urls = parse_sitemap("<not valid xml");
    assert!(urls.is_empty());
}

#[test]
fn robots_txt_result_has_default_shape() {
    let r = RobotsTxtResult::default();
    assert!(r.disallowed.is_empty());
    assert!(r.sitemaps.is_empty());
}
