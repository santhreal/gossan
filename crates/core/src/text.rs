//! Text utilities shared across gossan crates.

/// XML-escape the five pre-defined entities.
#[must_use]
pub fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// XML-unescape the five pre-defined entities.
#[must_use]
pub fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_escape_unescape_roundtrip() {
        let original = r#"<script>alert("xss")</script>"#;
        let escaped = xml_escape(original);
        let unescaped = xml_unescape(&escaped);
        assert_eq!(original, unescaped);
    }

    #[test]
    fn xml_unescape_decodes_ampersand_in_url() {
        let encoded = "https://example.com/page?a=1&amp;b=2";
        assert_eq!(
            xml_unescape(encoded),
            "https://example.com/page?a=1&b=2"
        );
    }
}
