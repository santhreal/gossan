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
    pub fn similarity(&self, length: usize, headers: &HashMap<String, String>, fuzzy_hash: u64, dom: &str) -> f64 {
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
                if val == v { header_matches += 1; }
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
    pub fn is_mirror(&self, length: usize, headers: &HashMap<String, String>, fuzzy_hash: u64, dom: &str) -> bool {
        self.similarity(length, headers, fuzzy_hash, dom) > 0.85
    }
}

/// Simple DOM fingerprinting: extracts tag names in order.
pub fn generate_dom_fingerprint(html: &str) -> String {
    let mut tags = Vec::new();
    let mut in_tag = false;
    let mut current_tag = String::new();

    for c in html.chars() {
        if c == '<' {
            in_tag = true;
            current_tag.clear();
        } else if c == '>' || c == ' ' || c == '/' {
            if in_tag && !current_tag.is_empty() {
                tags.push(current_tag.to_lowercase());
            }
            in_tag = false;
        } else if in_tag {
            current_tag.push(c);
        }
    }
    tags.join(",")
}

/// Simple 64-bit fuzzy hash (for demonstration, a legendary version would use SimHash).
pub fn calculate_fuzzy_hash(data: &str) -> u64 {
    use hashkit::wyhash;
    // We hash chunks of the data and XOR them to create a position-independent fingerprint
    let mut hash = 0u64;
    for chunk in data.as_bytes().chunks(64) {
        hash ^= wyhash::hash(chunk, 0);
    }
    hash
}
