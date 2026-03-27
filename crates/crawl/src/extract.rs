//! HTML extraction utilities — forms, links, and parameters.
//!
//! Pure functions that parse HTML and return structured data.
//! No HTTP requests, no side effects.

use gossan_core::DiscoveredForm;
use url::Url;

/// Extract all `<form>` elements from HTML, resolving action URLs against the base.
pub fn extract_forms(html: &str, base_url: &Url) -> Vec<DiscoveredForm> {
    let document = scraper::Html::parse_document(html);
    let form_selector = scraper::Selector::parse("form").expect("valid selector");
    let input_selector =
        scraper::Selector::parse("input, select, textarea").expect("valid selector");

    let mut forms = Vec::new();

    for form_el in document.select(&form_selector) {
        let action_raw = form_el.value().attr("action").unwrap_or("");
        let method = form_el
            .value()
            .attr("method")
            .unwrap_or("GET")
            .to_uppercase();

        // Resolve action URL against base
        let action = match base_url.join(action_raw) {
            Ok(resolved) => resolved.to_string(),
            Err(_) => continue,
        };

        let mut inputs = Vec::new();
        for input_el in form_el.select(&input_selector) {
            let name = match input_el.value().attr("name") {
                Some(n) if !n.is_empty() => n.to_string(),
                _ => continue,
            };
            let input_type = input_el
                .value()
                .attr("type")
                .unwrap_or("text")
                .to_lowercase();

            // Skip submit buttons and hidden CSRF tokens from the input list
            // (they're still sent but aren't fuzzable attack surface)
            if input_type == "submit" || input_type == "image" {
                continue;
            }

            inputs.push((name, input_type));
        }

        if !inputs.is_empty() {
            forms.push(DiscoveredForm {
                action,
                method,
                inputs,
            });
        }
    }

    forms
}

/// Extract all `<a href>` links from HTML, resolving against the base URL.
///
/// Returns only same-host links. Fragments and javascript: URLs are skipped.
pub fn extract_links(html: &str, base_url: &Url) -> Vec<Url> {
    let document = scraper::Html::parse_document(html);
    let link_selector = scraper::Selector::parse("a[href]").expect("valid selector");
    let base_host = base_url.host_str().unwrap_or("");

    let mut links = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for el in document.select(&link_selector) {
        let href = match el.value().attr("href") {
            Some(h) => h,
            None => continue,
        };

        // Skip non-HTTP schemes
        if href.starts_with("javascript:")
            || href.starts_with("mailto:")
            || href.starts_with("tel:")
            || href.starts_with('#')
        {
            continue;
        }

        let resolved = match base_url.join(href) {
            Ok(u) => u,
            Err(_) => continue,
        };

        // Only follow same-host links
        if resolved.host_str() != Some(base_host) {
            continue;
        }

        // Strip fragment for deduplication
        let mut clean = resolved.clone();
        clean.set_fragment(None);

        let key = clean.to_string();
        if seen.insert(key) {
            links.push(clean);
        }
    }

    links
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_forms_multiple() {
        let html = r#"
            <form action="/search" method="GET">
                <input name="q" type="text">
            </form>
            <form action="/contact" method="POST">
                <input name="email" type="email">
                <textarea name="message"></textarea>
                <input type="submit" value="Send">
            </form>
        "#;
        let base = Url::parse("https://example.com/").unwrap();
        let forms = extract_forms(html, &base);
        assert_eq!(forms.len(), 2);
        assert_eq!(forms[0].inputs.len(), 1);
        assert_eq!(forms[1].inputs.len(), 2); // submit is skipped
    }

    #[test]
    fn extract_forms_no_action() {
        let html = r#"<form><input name="q" type="text"></form>"#;
        let base = Url::parse("https://example.com/page").unwrap();
        let forms = extract_forms(html, &base);
        assert_eq!(forms.len(), 1);
        // Empty action resolves to current page
        assert_eq!(forms[0].action, "https://example.com/page");
    }

    #[test]
    fn extract_links_deduplicates() {
        let html = r#"
            <a href="/page">Page</a>
            <a href="/page">Page Again</a>
            <a href="/page#section">Page Section</a>
        "#;
        let base = Url::parse("https://example.com/").unwrap();
        let links = extract_links(html, &base);
        // /page and /page#section should deduplicate to one link
        assert_eq!(links.len(), 1);
    }

    #[test]
    fn extract_links_skips_javascript() {
        let html = r#"
            <a href="javascript:void(0)">JS</a>
            <a href="mailto:test@example.com">Mail</a>
            <a href="/real">Real</a>
        "#;
        let base = Url::parse("https://example.com/").unwrap();
        let links = extract_links(html, &base);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].path(), "/real");
    }

    #[test]
    fn extract_forms_select_element() {
        let html = r#"
            <form action="/filter" method="GET">
                <select name="category">
                    <option value="a">A</option>
                    <option value="b">B</option>
                </select>
                <input name="search" type="text">
            </form>
        "#;
        let base = Url::parse("https://example.com/").unwrap();
        let forms = extract_forms(html, &base);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].inputs.len(), 2);
        assert!(forms[0].inputs.iter().any(|(n, _)| n == "category"));
    }

    // ── Adversarial edge cases ──────────────────────────────────────────────

    #[test]
    fn extract_forms_empty_html() {
        let base = Url::parse("https://example.com/").unwrap();
        assert!(extract_forms("", &base).is_empty());
        assert!(extract_links("", &base).is_empty());
    }

    #[test]
    fn extract_forms_malformed_unclosed_tags() {
        let html = r#"
            <form action="/broken" method="POST">
                <input name="field1" type="text">
                <div><input name="field2" type="hidden">
                <!-- unclosed div and form -->
        "#;
        let base = Url::parse("https://example.com/").unwrap();
        let forms = extract_forms(html, &base);
        // scraper should still parse what it can — form with at least the hidden input
        assert!(
            !forms.is_empty(),
            "should extract forms even from malformed HTML"
        );
    }

    #[test]
    fn extract_forms_skips_no_inputs() {
        let html = r#"<form action="/empty"></form>"#;
        let base = Url::parse("https://example.com/").unwrap();
        let forms = extract_forms(html, &base);
        assert!(forms.is_empty(), "form with no inputs should be skipped");
    }

    #[test]
    fn extract_forms_deeply_nested() {
        let html = r#"
            <div><div><div><div><div><div><div><div>
                <form action="/deep" method="POST">
                    <input name="deep_field" type="text">
                </form>
            </div></div></div></div></div></div></div></div>
        "#;
        let base = Url::parse("https://example.com/").unwrap();
        let forms = extract_forms(html, &base);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].inputs[0].0, "deep_field");
    }

    #[test]
    fn extract_links_skips_data_uris() {
        let html = r#"
            <a href="data:text/html,<h1>test</h1>">Data</a>
            <a href="/real">Real</a>
        "#;
        let base = Url::parse("https://example.com/").unwrap();
        let links = extract_links(html, &base);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].path(), "/real");
    }

    #[test]
    fn extract_links_skips_tel() {
        let html = r#"<a href="tel:+1234567890">Call</a><a href="/page">Page</a>"#;
        let base = Url::parse("https://example.com/").unwrap();
        let links = extract_links(html, &base);
        assert_eq!(links.len(), 1);
    }

    #[test]
    fn extract_links_handles_empty_href() {
        let html = r#"<a href="">Empty</a><a href="/real">Real</a>"#;
        let base = Url::parse("https://example.com/page").unwrap();
        let links = extract_links(html, &base);
        // Empty href resolves to current page — should be valid
        assert!(!links.is_empty());
    }

    #[test]
    fn extract_forms_unicode_attributes() {
        let html =
            r#"<form action="/búsqueda" method="GET"><input name="consulta" type="text"></form>"#;
        let base = Url::parse("https://example.com/").unwrap();
        let forms = extract_forms(html, &base);
        assert_eq!(forms.len(), 1);
        assert!(forms[0].action.contains("b%C3%BAsqueda") || forms[0].action.contains("búsqueda"));
    }

    #[test]
    fn extract_links_massive_html_no_panic() {
        // 1000 links — should not panic or OOM
        let links_html: String = (0..1000)
            .map(|i| format!(r#"<a href="/page-{i}">Link {i}</a>"#))
            .collect::<Vec<_>>()
            .join("\n");
        let base = Url::parse("https://example.com/").unwrap();
        let links = extract_links(&links_html, &base);
        assert_eq!(links.len(), 1000);
    }

    #[test]
    fn extract_forms_method_defaults_to_get() {
        let html = r#"<form action="/default"><input name="q" type="text"></form>"#;
        let base = Url::parse("https://example.com/").unwrap();
        let forms = extract_forms(html, &base);
        assert_eq!(forms[0].method, "GET");
    }
}
