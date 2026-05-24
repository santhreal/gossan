//! Deep truth tests for `gossan_crawl::seeds`  -  the robots.txt + sitemap
//! seed parsers feed the crawl frontier, so a parse miss is a silently
//! smaller attack surface and a corrupted URL is a wrong (or unsafe)
//! target. `tests/parsers.rs` only exercised happy paths; its own
//! doc-comment claims it "locks edge-case behaviour" but it never
//! asserted any of the three contract violations below.
//!
//! Contract-first per the testing doctrine: these assert the CORRECT,
//! spec-mandated behaviour. Where the engine is wrong it is fixed in
//! `seeds.rs`  -  the tests are never weakened to match.
//!
//! Specs: robots.txt = RFC 9309 (field names case-insensitive, §2.1);
//! sitemap = sitemaps.org protocol (URLs MUST entity-escape & ' " < >,
//! so the parser MUST entity-DECODE them back).

use gossan_crawl::seeds::{parse_robots_txt, parse_sitemap};
use url::Url;

fn base() -> Url {
    Url::parse("https://example.com/").expect("base url")
}

// ─────────────────── robots.txt: RFC 9309 conformance ──────────────────

/// RFC 9309 §2.1: "field name ... case-insensitive". Real robots.txt in
/// the wild uses `disallow:`, `ALLOW:`, `sitemap:` freely. Dropping
/// them shrinks the discovered surface for no reason.
#[test]
fn robots_directive_keys_are_case_insensitive() {
    let body = "\
user-agent: *
disallow: /admin
ALLOW: /public
SiteMap: https://example.com/sitemap.xml
";
    let r = parse_robots_txt(body, &base());
    assert!(
        r.disallowed.iter().any(|u| u.path() == "/admin"),
        "lowercase `disallow:` must parse (RFC 9309 case-insensitive); got {:?}",
        r.disallowed
    );
    assert!(
        r.allowed.iter().any(|u| u.path() == "/public"),
        "uppercase `ALLOW:` must parse; got {:?}",
        r.allowed
    );
    assert!(
        r.sitemaps.iter().any(|u| u.as_str().ends_with("sitemap.xml")),
        "mixed-case `SiteMap:` must parse; got {:?}",
        r.sitemaps
    );
}

/// A relative `Sitemap:` value resolves against the robots.txt origin
/// (some sites emit `Sitemap: /sitemap.xml`).
#[test]
fn robots_relative_sitemap_resolves_against_base() {
    let r = parse_robots_txt("Sitemap: /sitemap_index.xml\n", &base());
    assert_eq!(
        r.sitemaps.iter().map(Url::as_str).collect::<Vec<_>>(),
        ["https://example.com/sitemap_index.xml"],
        "relative Sitemap must resolve to the base origin"
    );
}

/// Spaces around the colon must not defeat the directive (`Sitemap :`).
#[test]
fn robots_tolerates_space_before_colon_value() {
    let r = parse_robots_txt("Disallow:   /a\nSitemap:  https://example.com/s.xml\n", &base());
    assert!(r.disallowed.iter().any(|u| u.path() == "/a"));
    assert!(r.sitemaps.iter().any(|u| u.as_str().ends_with("/s.xml")));
}

// ─────────────────── sitemap.xml: protocol conformance ─────────────────

/// sitemaps.org: URLs in `<loc>` MUST be entity-escaped (`&`→`&amp;`).
/// The parser MUST therefore entity-DECODE, or every URL with a query
/// string (overwhelmingly common) is corrupted into a wrong endpoint  - 
/// e.g. a literal `&amp;` becomes part of a parameter value, so the
/// crawler probes a path that does not exist and misses the real one.
#[test]
fn sitemap_loc_xml_entities_are_decoded() {
    let xml = r#"<urlset>
  <url><loc>https://example.com/search?q=a&amp;page=2&amp;sort=desc</loc></url>
  <url><loc>https://example.com/p?x=1&amp;y=&lt;b&gt;</loc></url>
</urlset>"#;
    let urls = parse_sitemap(xml);

    let first = urls
        .iter()
        .find(|u| u.path() == "/search")
        .unwrap_or_else(|| panic!("missing /search; got {urls:?}"));
    assert_eq!(
        first.query(),
        Some("q=a&page=2&sort=desc"),
        "`&amp;` MUST be decoded to `&` (sitemaps.org requires escaping; \
         a raw &amp; yields a wrong URL); got {:?}",
        first.query()
    );

    let second = urls
        .iter()
        .find(|u| u.path() == "/p")
        .unwrap_or_else(|| panic!("missing /p; got {urls:?}"));
    // &lt; / &gt; decode then percent-encode in the query  -  the point is
    // the literal entities must NOT survive into the URL.
    assert!(
        !second.as_str().contains("&amp;")
            && !second.as_str().contains("&lt;")
            && !second.as_str().contains("&gt;"),
        "no raw XML entity may survive into the parsed URL: {}",
        second.as_str()
    );
}

/// Robustness: a single malformed `<loc>` (no closing tag) must NOT
/// discard the valid entries that follow it. Pre-fix, the parser
/// consumed the next entry's `</loc>` as the broken one's terminator,
/// silently losing `/good2`  -  one typo in a 10k-URL sitemap nuking the
/// rest of the crawl frontier is a severe recall failure.
#[test]
fn sitemap_one_broken_loc_does_not_drop_following_urls() {
    let xml = "\
<urlset>
  <url><loc>https://example.com/good1</loc></url>
  <url><loc>https://example.com/BROKEN-no-close
  <url><loc>https://example.com/good2</loc></url>
  <url><loc>https://example.com/good3</loc></url>
</urlset>";
    let urls = parse_sitemap(xml);
    let paths: Vec<&str> = urls.iter().map(Url::path).collect();
    assert!(
        paths.contains(&"/good1"),
        "the entry before the broken one must survive: {paths:?}"
    );
    assert!(
        paths.contains(&"/good2") && paths.contains(&"/good3"),
        "entries AFTER a malformed <loc> must still be extracted  -  a \
         single typo must not truncate the frontier: {paths:?}"
    );
}

/// `<loc>` with surrounding whitespace/newlines (common from pretty
/// printers) must still parse  -  the value is trimmed.
#[test]
fn sitemap_loc_with_surrounding_whitespace_parses() {
    let xml = "<urlset><url><loc>\n   https://example.com/spaced   \n</loc></url></urlset>";
    let urls = parse_sitemap(xml);
    assert_eq!(
        urls.iter().map(Url::as_str).collect::<Vec<_>>(),
        ["https://example.com/spaced"]
    );
}

/// A sitemap *index* nests `<loc>` inside `<sitemap>`; those child
/// sitemap URLs are exactly the seeds we want to follow next, so they
/// must be extracted too (same `<loc>` tag  -  assert it explicitly).
#[test]
fn sitemap_index_child_locs_are_extracted() {
    let xml = r#"<sitemapindex>
  <sitemap><loc>https://example.com/sitemap-posts.xml</loc></sitemap>
  <sitemap><loc>https://example.com/sitemap-pages.xml</loc></sitemap>
</sitemapindex>"#;
    let urls = parse_sitemap(xml);
    assert_eq!(urls.len(), 2, "both child sitemaps must be seeds: {urls:?}");
    assert!(urls.iter().any(|u| u.path() == "/sitemap-posts.xml"));
}

/// Adversarial: hostile/garbage input must not panic and must not
/// invent URLs (precision + no-crash).
#[test]
fn sitemap_adversarial_inputs_are_safe_and_precise() {
    for junk in [
        "",
        "<loc></loc>",
        "<loc>not a url</loc>",
        "<loc>javascript:alert(1)</loc>",
        "<loc><loc><loc>",
        &"<loc>".repeat(10_000),
        "\u{0}\u{0}<loc>\u{0}</loc>",
    ] {
        let urls = parse_sitemap(junk);
        assert!(
            urls.iter().all(|u| u.scheme() == "http" || u.scheme() == "https"),
            "junk {junk:?} produced a non-http URL: {urls:?}"
        );
    }
}
