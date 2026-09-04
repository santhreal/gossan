//! Version accuracy tracking for backport-aware CVE correlation.
//!
//! Flags targets where version strings may be unreliable due to
//! distribution backporting (e.g. Debian, RHEL).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a structural baseline for a host's HTTP responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseBaseline {
    /// The average response length for garbage paths.
    pub avg_length: usize,
    /// Dominant headers (e.g. Server, X-Powered-By) seen in error responses.
    pub headers: HashMap<String, String>,
    /// Fuzzy hash of the response body (MinHash or SimHash).
    pub fuzzy_hash: u64,
    /// Simple tag-based fingerprint of the DOM (e.g. "html,head,title,body,div,p").
    pub dom_fingerprint: String,
}

impl ResponseBaseline {
    /// Returns a similarity score (0.0 to 1.0) between this baseline and a new response.
    pub fn similarity(
        &self,
        length: usize,
        headers: &HashMap<String, String>,
        fuzzy_hash: u64,
        dom: &str,
    ) -> f64 {
        let mut score = 0.0;
        let mut weights = 0.0;

        // 1. DOM similarity (40% weight) - Structural identity is king
        weights += 0.4;
        if self.dom_fingerprint == dom {
            score += 0.4;
        }

        // 2. Header similarity (30% weight)
        weights += 0.3;
        let mut header_matches = 0;
        for (k, v) in &self.headers {
            if let Some(val) = headers.get(k) {
                if val == v {
                    header_matches += 1;
                }
            }
        }
        if !self.headers.is_empty() {
            score += (header_matches as f64 / self.headers.len() as f64) * 0.3;
        }

        // 3. Length similarity (20% weight)
        weights += 0.2;
        let len_diff = (self.avg_length as f64 - length as f64).abs();
        let len_sim = (1.0 - (len_diff / self.avg_length.max(1) as f64)).max(0.0);
        score += len_sim * 0.2;

        // 4. Fuzzy hash similarity (10% weight) - Content match is secondary for mirrors
        weights += 0.1;
        if self.fuzzy_hash == fuzzy_hash {
            score += 0.1;
        }

        score / weights
    }

    /// Determines if a response is a "Mirror" (True) or a "Signal" (False).
    pub fn is_mirror(
        &self,
        length: usize,
        headers: &HashMap<String, String>,
        fuzzy_hash: u64,
        dom: &str,
    ) -> bool {
        self.similarity(length, headers, fuzzy_hash, dom) > 0.85
    }
}

/// Simple DOM fingerprinting: extracts tag names in order.
///
/// Handles `>` inside quoted attributes and ignores content inside
/// `<script>` / `<style>` tags so that `<div>` literals inside JS/CSS
/// are not misidentified as real tags.
pub fn generate_dom_fingerprint(html: &str) -> String {
    let mut tags = Vec::new();
    let mut in_tag = false;
    let mut in_quote = false;
    let mut quote_char = '\0';
    let mut current_tag = String::new();
    let mut in_script = false;
    let mut in_style = false;

    let chars: Vec<char> = html.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];

        if in_tag && in_quote {
            if c == quote_char {
                in_quote = false;
            }
            i += 1;
            continue;
        }

        if c == '<' {
            // Peek ahead to detect closing script/style
            if in_script {
                let rest: String = chars[i..].iter().take(9).collect();
                if rest.to_lowercase().starts_with("</script>") {
                    in_script = false;
                }
            }
            if in_style {
                let rest: String = chars[i..].iter().take(8).collect();
                if rest.to_lowercase().starts_with("</style>") {
                    in_style = false;
                }
            }

            if !in_script && !in_style {
                in_tag = true;
                current_tag.clear();
            }
        } else if in_tag && (c == '"' || c == '\'') {
            in_quote = true;
            quote_char = c;
            if !current_tag.is_empty() {
                tags.push(current_tag.to_lowercase());
                current_tag.clear();
            }
        } else if c == '>' || c == ' ' || c == '/' || c == '\t' || c == '\n' || c == '\r' {
            if in_tag && !current_tag.is_empty() {
                let tag_name = current_tag.to_lowercase();
                if tag_name == "script" {
                    in_script = true;
                } else if tag_name == "style" {
                    in_style = true;
                }
                tags.push(tag_name);
            }
            in_tag = false;
        } else if in_tag {
            current_tag.push(c);
        }
        i += 1;
    }
    tags.join(",")
}

/// 64-bit SimHash over whitespace-separated tokens.
///
/// Nearby documents (small edit distance / shared tokens) share most
/// bits; a single-byte change in a long body no longer flips the entire
/// fingerprint the way the previous XOR-of-wyhash block hash did.
pub fn calculate_fuzzy_hash(data: &str) -> u64 {
    use hashkit::wyhash;
    let mut weights = [0i32; 64];
    let mut any = false;
    for token in data.split_whitespace() {
        if token.is_empty() {
            continue;
        }
        any = true;
        let h = wyhash::hash(token.as_bytes(), 0);
        for bit in 0..64 {
            if (h >> bit) & 1 == 1 {
                weights[bit] += 1;
            } else {
                weights[bit] -= 1;
            }
        }
    }
    if !any {
        // Empty / whitespace-only input: fall back to a stable hash of
        // the raw bytes so the function remains total.
        return wyhash::hash(data.as_bytes(), 0);
    }
    let mut out = 0u64;
    for bit in 0..64 {
        if weights[bit] > 0 {
            out |= 1u64 << bit;
        }
    }
    out
}


#[cfg(test)]
mod fuzzy_hash_tests {
    use super::*;

    #[test]
    fn fuzzy_hash_tolerates_small_edit() {
        let a = "the quick brown fox jumps over the lazy dog and then some more words follow here";
        let b = "the quick brown fox jumps over the lazy dog and then some more words follow here!";
        let ha = calculate_fuzzy_hash(a);
        let hb = calculate_fuzzy_hash(b);
        let dist = (ha ^ hb).count_ones();
        assert!(dist <= 8, "small edit should keep hamming distance low, got {dist}");
    }

    #[test]
    fn fuzzy_hash_empty_input_is_deterministic() {
        let h1 = calculate_fuzzy_hash("");
        let h2 = calculate_fuzzy_hash("");
        assert_eq!(h1, h2, "empty input must produce a stable hash");
    }

    #[test]
    fn fuzzy_hash_whitespace_only_is_deterministic() {
        let h1 = calculate_fuzzy_hash("   \t\n  ");
        let h2 = calculate_fuzzy_hash("   \t\n  ");
        assert_eq!(h1, h2, "whitespace-only input must produce a stable hash");
    }
}

#[cfg(test)]
mod dom_fingerprint_tests {
    use super::*;

    #[test]
    fn extracts_tag_names_in_order() {
        let html = "<html><head><title>Test</title></head><body><div><p>Hello</p></div></body></html>";
        let fp = generate_dom_fingerprint(html);
        assert_eq!(fp, "html,head,title,body,div,p");
    }

    #[test]
    fn ignores_closing_tags() {
        let html = "<div><span>text</span></div>";
        let fp = generate_dom_fingerprint(html);
        assert_eq!(fp, "div,span");
    }

    #[test]
    fn handles_self_closing_tags() {
        let html = "<div><br/><img src=\"x\"/></div>";
        let fp = generate_dom_fingerprint(html);
        assert_eq!(fp, "div,br,img");
    }

    #[test]
    fn ignores_tag_content_in_script() {
        let html = "<div><script>var x = '<div>fake</div>';</script><span>real</span></div>";
        let fp = generate_dom_fingerprint(html);
        assert_eq!(fp, "div,script,span");
    }

    #[test]
    fn ignores_tag_content_in_style() {
        let html = "<div><style>.div { color: red; }</style></div>";
        let fp = generate_dom_fingerprint(html);
        assert_eq!(fp, "div,style");
    }

    #[test]
    fn handles_attributes_with_quoted_values() {
        let html = "<div class=\"foo bar\" id='baz'>text</div>";
        let fp = generate_dom_fingerprint(html);
        assert_eq!(fp, "div");
    }

    #[test]
    fn empty_html_produces_empty_fingerprint() {
        assert_eq!(generate_dom_fingerprint(""), "");
    }

    #[test]
    fn plain_text_produces_empty_fingerprint() {
        assert_eq!(generate_dom_fingerprint("just text, no tags"), "");
    }

    #[test]
    fn case_insensitive_tag_names() {
        let html = "<DIV><SPAN>text</SPAN></DIV>";
        let fp = generate_dom_fingerprint(html);
        assert_eq!(fp, "div,span");
    }
}

#[cfg(test)]
mod response_baseline_tests {
    use super::*;

    #[test]
    fn identical_response_is_mirror() {
        let baseline = ResponseBaseline {
            avg_length: 100,
            headers: [("Server".to_string(), "nginx".to_string())].into(),
            fuzzy_hash: 42,
            dom_fingerprint: "html,head,body".to_string(),
        };
        assert!(
            baseline.is_mirror(100, &baseline.headers.clone(), 42, "html,head,body"),
            "identical response must be classified as mirror"
        );
    }

    #[test]
    fn completely_different_response_is_not_mirror() {
        let baseline = ResponseBaseline {
            avg_length: 100,
            headers: [("Server".to_string(), "nginx".to_string())].into(),
            fuzzy_hash: 42,
            dom_fingerprint: "html,head,body".to_string(),
        };
        let different_headers = [("Server".to_string(), "apache".to_string())].into();
        assert!(
            !baseline.is_mirror(500, &different_headers, 999, "div,span,p"),
            "completely different response must not be classified as mirror"
        );
    }

    #[test]
    fn similarity_score_is_between_zero_and_one() {
        let baseline = ResponseBaseline {
            avg_length: 100,
            headers: [("Server".to_string(), "nginx".to_string())].into(),
            fuzzy_hash: 42,
            dom_fingerprint: "html,head,body".to_string(),
        };
        let different_headers = [("Server".to_string(), "apache".to_string())].into();
        let score = baseline.similarity(200, &different_headers, 0, "div,span");
        assert!(score >= 0.0 && score <= 1.0, "similarity score must be in [0, 1], got {score}");
    }
}
