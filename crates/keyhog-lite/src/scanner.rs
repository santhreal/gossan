//! CPU-only scanner: aho-corasick keyword prefilter + per-detector
//! regex match. Mirrors upstream `keyhog_scanner::CompiledScanner` in
//! shape; no SIMD, no GPU.

use crate::{Detector, Severity};
use aho_corasick::{AhoCorasick, AhoCorasickKind};
use regex::Regex;
use thiserror::Error;

/// A unit of content presented to the scanner. JS bodies, repo blobs,
/// and CLI stdin all flow through `Chunk`.
#[derive(Debug, Clone, Default)]
pub struct Chunk {
    /// Raw content. UTF-8 is assumed; binary callers must lossy-decode
    /// before constructing the chunk.
    pub data: String,
    /// Provenance + source tags.
    pub metadata: ChunkMetadata,
}

/// Where this chunk came from. Used to populate `MatchLocation` on each
/// emitted match.
#[derive(Debug, Clone, Default)]
pub struct ChunkMetadata {
    /// Free-form source label (`js`, `scm`, `crawl`, `stdin`).
    pub source_type: String,
    /// Source path / URL when applicable.
    pub path: Option<String>,
    /// Git commit SHA when scanning a repo blob.
    pub commit: Option<String>,
    /// Commit author (for repo blobs).
    pub author: Option<String>,
    /// Commit date (for repo blobs).
    pub date: Option<String>,
}

/// A single secret match emitted by the scanner.
#[derive(Debug, Clone)]
pub struct Match {
    /// Detector that fired (`aws-access-key`).
    pub detector_id: String,
    /// Detector display name.
    pub detector_name: String,
    /// Service label.
    pub service: String,
    /// Severity carried from the detector.
    pub severity: Severity,
    /// The matched substring (raw — keep out of serialized outputs).
    pub credential: String,
    /// 1-based byte offset of the match start in the chunk data.
    pub byte_offset: usize,
    /// Where the match lives.
    pub location: MatchLocation,
}

/// Coordinates of a match inside the chunk + caller-supplied provenance.
#[derive(Debug, Clone, Default)]
pub struct MatchLocation {
    /// Source label (`js`, `scm`).
    pub source: String,
    /// File path or URL.
    pub file_path: Option<String>,
    /// 1-based line number, when computable from the chunk.
    pub line: Option<usize>,
    /// Byte offset from start of chunk.
    pub offset: usize,
    /// Commit SHA when applicable.
    pub commit: Option<String>,
    /// Commit author when applicable.
    pub author: Option<String>,
    /// Commit date when applicable.
    pub date: Option<String>,
}

/// Errors raised at compile time. Runtime scan never fails — bad
/// chunks are returned with empty matches.
#[derive(Debug, Error)]
pub enum ScannerError {
    /// A detector's regex pattern failed to compile.
    #[error("regex compile failure in detector {detector_id}: {source}")]
    Regex {
        /// Detector that owned the bad regex.
        detector_id: String,
        /// Underlying regex error.
        #[source]
        source: regex::Error,
    },
    /// Aho-Corasick keyword set failed to build (only happens on
    /// empty / overlapping pathological inputs).
    #[error("keyword prefilter build failed: {0}")]
    Prefilter(String),
}

struct CompiledDetector {
    meta_id: String,
    meta_name: String,
    service: String,
    severity: Severity,
    patterns: Vec<CompiledPattern>,
    companions: Vec<CompiledCompanion>,
    keyword_idx_range: Option<(usize, usize)>,
}

struct CompiledPattern {
    regex: Regex,
    #[allow(dead_code)]
    description: String,
}

struct CompiledCompanion {
    regex: Regex,
    within_lines: u32,
    #[allow(dead_code)]
    name: Option<String>,
    required: bool,
}

/// Compiled scanner. Build once; share across threads via `&self`
/// (everything inside is immutable after `compile`).
pub struct CompiledScanner {
    detectors: Vec<CompiledDetector>,
    keyword_filter: Option<AhoCorasick>,
    /// Map from keyword index → detector index. Lets the prefilter
    /// route a hit to the right detector without re-scanning.
    keyword_to_detector: Vec<usize>,
}

impl CompiledScanner {
    /// Compile a set of detectors. Bad regexes return
    /// `ScannerError::Regex` and the whole compile aborts — callers
    /// that want best-effort skip-on-error semantics should filter
    /// detectors before calling.
    pub fn compile(detectors: Vec<Detector>) -> Result<Self, ScannerError> {
        let mut compiled = Vec::with_capacity(detectors.len());
        let mut all_keywords: Vec<String> = Vec::new();
        let mut keyword_to_detector: Vec<usize> = Vec::new();

        for (det_idx, d) in detectors.into_iter().enumerate() {
            let meta_id = d.meta.id.clone();
            let mut patterns = Vec::with_capacity(d.meta.patterns.len());
            for p in &d.meta.patterns {
                let re = Regex::new(&p.regex).map_err(|e| ScannerError::Regex {
                    detector_id: meta_id.clone(),
                    source: e,
                })?;
                patterns.push(CompiledPattern {
                    regex: re,
                    description: p.description.clone(),
                });
            }
            let mut companions = Vec::with_capacity(d.meta.companions.len());
            for c in &d.meta.companions {
                let re = Regex::new(&c.regex).map_err(|e| ScannerError::Regex {
                    detector_id: meta_id.clone(),
                    source: e,
                })?;
                companions.push(CompiledCompanion {
                    regex: re,
                    within_lines: c.within_lines,
                    name: c.name.clone(),
                    required: c.required,
                });
            }

            let keyword_idx_range = if d.meta.keywords.is_empty() {
                None
            } else {
                let start = all_keywords.len();
                for k in &d.meta.keywords {
                    all_keywords.push(k.clone());
                    keyword_to_detector.push(det_idx);
                }
                Some((start, all_keywords.len()))
            };

            compiled.push(CompiledDetector {
                meta_id,
                meta_name: d.meta.name,
                service: d.meta.service,
                severity: d.meta.severity,
                patterns,
                companions,
                keyword_idx_range,
            });
        }

        let keyword_filter = if all_keywords.is_empty() {
            None
        } else {
            let ac = AhoCorasick::builder()
                .kind(Some(AhoCorasickKind::DFA))
                .build(&all_keywords)
                .map_err(|e| ScannerError::Prefilter(e.to_string()))?;
            Some(ac)
        };

        Ok(Self {
            detectors: compiled,
            keyword_filter,
            keyword_to_detector,
        })
    }

    /// True when no detectors are loaded — handy in callers that want
    /// to short-circuit the chunk-building cost.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }

    /// Run the scanner over a single chunk. Returns one `Match` per
    /// hit; multiple detectors and multiple patterns can fire on the
    /// same byte range. Caller is responsible for downstream dedup
    /// via [`crate::dedup_matches`].
    #[must_use]
    pub fn scan(&self, chunk: &Chunk) -> Vec<Match> {
        if self.detectors.is_empty() {
            return Vec::new();
        }
        let data = &chunk.data;

        // Phase 1: aho-corasick prefilter. Map keyword hits → detector
        // indices, dedup. Detectors with no keywords always run.
        let mut to_scan: Vec<bool> = vec![false; self.detectors.len()];
        let mut any_no_keyword = false;
        for (idx, det) in self.detectors.iter().enumerate() {
            if det.keyword_idx_range.is_none() {
                to_scan[idx] = true;
                any_no_keyword = true;
            }
        }
        if let Some(ac) = &self.keyword_filter {
            for hit in ac.find_iter(data) {
                let kw_idx = hit.pattern().as_usize();
                if let Some(det_idx) = self.keyword_to_detector.get(kw_idx) {
                    to_scan[*det_idx] = true;
                }
            }
        }
        if !any_no_keyword && to_scan.iter().all(|b| !*b) {
            return Vec::new();
        }

        // Phase 2: regex match on each candidate detector. Line numbers
        // are computed lazily — only when we actually have a hit, walk
        // the data once and remember newline offsets so subsequent
        // hits in the same chunk are O(log n) lookups.
        let mut newlines: Option<Vec<usize>> = None;
        let mut out = Vec::new();

        for (det_idx, det) in self.detectors.iter().enumerate() {
            if !to_scan[det_idx] {
                continue;
            }
            // A detector with ≥1 required companion only fires when at
            // least one of those companions is also present in the
            // chunk within its `within_lines` window. This is the
            // single biggest false-positive reducer — providers like
            // Twilio / Stripe / Avalara use it to require the
            // secret-half of a credential pair to be co-located with
            // the public-half before flagging.
            let required_companions: Vec<&CompiledCompanion> =
                det.companions.iter().filter(|c| c.required).collect();
            for pat in &det.patterns {
                for m in pat.regex.find_iter(data) {
                    if newlines.is_none() {
                        newlines = Some(data.match_indices('\n').map(|(i, _)| i).collect());
                    }
                    let nl = newlines.as_ref().expect("computed above");
                    let line = match nl.binary_search(&m.start()) {
                        Ok(i) | Err(i) => i + 1,
                    };

                    if !required_companions.is_empty()
                        && !any_companion_within(data, nl, line, &required_companions)
                    {
                        continue;
                    }

                    // Test-string allowlist: drop matches that smell
                    // like documentation placeholders. We check both
                    // the credential itself AND the line surrounding
                    // it — variable names like `TEST_JWT = "eyJ..."`
                    // never carry the placeholder marker on the
                    // credential side, but the line does.
                    let line_text = line_at(data, nl, line);
                    if looks_like_placeholder(m.as_str()) || looks_like_placeholder(line_text) {
                        continue;
                    }

                    out.push(Match {
                        detector_id: det.meta_id.clone(),
                        detector_name: det.meta_name.clone(),
                        service: det.service.clone(),
                        severity: det.severity,
                        credential: m.as_str().to_string(),
                        byte_offset: m.start(),
                        location: MatchLocation {
                            source: chunk.metadata.source_type.clone(),
                            file_path: chunk.metadata.path.clone(),
                            line: Some(line),
                            offset: m.start(),
                            commit: chunk.metadata.commit.clone(),
                            author: chunk.metadata.author.clone(),
                            date: chunk.metadata.date.clone(),
                        },
                    });
                }
            }
        }

        out
    }
}

/// Return the text of the `line`-th line (1-based) given pre-computed
/// newline offsets. Empty string if the line is past EOF.
fn line_at<'a>(data: &'a str, newlines: &[usize], line: usize) -> &'a str {
    let start = if line <= 1 {
        0
    } else {
        let prev = newlines.get(line - 2).copied().unwrap_or(0);
        // newline at `prev` belongs to the previous line; line starts
        // one byte after.
        prev.saturating_add(1).min(data.len())
    };
    let end = newlines
        .get(line - 1)
        .copied()
        .unwrap_or(data.len())
        .min(data.len());
    if start >= end {
        return "";
    }
    &data[start..end]
}

/// Heuristic: does the credential look like a documentation
/// placeholder rather than a real secret? Upstream keyhog uses a
/// proper Allowlist with regex rules; we approximate with a fixed
/// substring list that covers the common ASCII placeholder
/// conventions found in clean corpora. False negatives here are fine
/// — a real secret containing the substring "EXAMPLE" is exotic
/// enough that downgrading is acceptable.
fn looks_like_placeholder(credential: &str) -> bool {
    const MARKERS: &[&str] = &[
        "EXAMPLE",
        "example",
        "PLACEHOLDER",
        "placeholder",
        "FAKE",
        "fake",
        "your_",
        "YOUR_",
        "REPLACE_",
        "replace_",
        "dummy",
        "DUMMY",
        "TODO",
        "<your",
        "<insert",
        "INSERT_",
        "xxxxx",
        "XXXXX",
        // common test-fixture conventions
        "_test_",
        "TEST_",
        "not_a_real",
        "NOT_A_REAL",
        "fakefake",
        // AWS docs canonical example access key. Including by literal
        // ID so the canonical value never trips the scanner even if a
        // user pastes it verbatim.
        "AKIAIOSFODNN7EXAMPLE",
    ];
    for m in MARKERS {
        if credential.contains(m) {
            return true;
        }
    }
    false
}

/// True if at least one of `companions` matches somewhere in `data`
/// within `within_lines` of the primary-match line.
fn any_companion_within(
    data: &str,
    newlines: &[usize],
    primary_line: usize,
    companions: &[&CompiledCompanion],
) -> bool {
    for c in companions {
        for m in c.regex.find_iter(data) {
            let mline = match newlines.binary_search(&m.start()) {
                Ok(i) | Err(i) => i + 1,
            };
            let dist = if mline > primary_line {
                mline - primary_line
            } else {
                primary_line - mline
            };
            if dist as u32 <= c.within_lines {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Detector;

    fn aws_detector() -> Detector {
        toml::from_str(
            r#"
[detector]
id = "aws-access-key"
name = "AWS Access Key"
service = "aws"
severity = "critical"
keywords = ["AKIA", "ASIA"]
[[detector.patterns]]
regex = "(AKIA|ASIA)[0-9A-Z]{16}"
description = "AWS access key ID"
"#,
        )
        .expect("aws detector parses")
    }

    fn no_keyword_detector() -> Detector {
        toml::from_str(
            r#"
[detector]
id = "uuid-secret"
name = "UUID-shaped Secret"
service = "generic"
severity = "low"
[[detector.patterns]]
regex = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
"#,
        )
        .expect("uuid detector parses")
    }

    #[test]
    fn scan_aws_access_key_positive() {
        let s = CompiledScanner::compile(vec![aws_detector()]).expect("compile");
        let chunk = Chunk {
            data: "const k = \"AKIA1234567890ABCDEF\"".into(),
            metadata: ChunkMetadata {
                source_type: "js".into(),
                path: Some("https://example.com/app.js".into()),
                ..Default::default()
            },
        };
        let m = s.scan(&chunk);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].detector_id, "aws-access-key");
        assert_eq!(m[0].credential, "AKIA1234567890ABCDEF");
        assert_eq!(m[0].severity, Severity::Critical);
        assert_eq!(m[0].location.line, Some(1));
        assert_eq!(
            m[0].location.file_path.as_deref(),
            Some("https://example.com/app.js")
        );
    }

    #[test]
    fn scan_aws_access_key_negative_no_keyword_no_scan() {
        // Without "AKIA" or "ASIA" in the body the prefilter should
        // skip this detector entirely.
        let s = CompiledScanner::compile(vec![aws_detector()]).expect("compile");
        let chunk = Chunk {
            data: "nothing to see here, just some text".into(),
            metadata: ChunkMetadata::default(),
        };
        assert!(s.scan(&chunk).is_empty());
    }

    #[test]
    fn placeholder_aws_access_key_does_not_fire() {
        // The canonical AWS docs example key; must be treated as a
        // placeholder, not a real secret.
        let s = CompiledScanner::compile(vec![aws_detector()]).expect("compile");
        let chunk = Chunk {
            data: "const k = \"AKIAIOSFODNN7EXAMPLE\"".into(),
            metadata: ChunkMetadata::default(),
        };
        assert!(s.scan(&chunk).is_empty());
    }

    #[test]
    fn placeholder_example_in_credential_does_not_fire() {
        // 20-char key whose tail contains the substring "EXAMPLE".
        let s = CompiledScanner::compile(vec![aws_detector()]).expect("compile");
        let chunk = Chunk {
            data: "let k = \"AKIAEXAMPLE012345678\";".into(),
            metadata: ChunkMetadata::default(),
        };
        assert!(s.scan(&chunk).is_empty());
    }

    #[test]
    fn scan_aws_access_key_negative_keyword_match_but_pattern_fails() {
        // "AKIA" is present but the trailing 16 chars are too short.
        let s = CompiledScanner::compile(vec![aws_detector()]).expect("compile");
        let chunk = Chunk {
            data: "comment about AKIA tokens".into(),
            metadata: ChunkMetadata::default(),
        };
        assert!(s.scan(&chunk).is_empty());
    }

    #[test]
    fn scan_detector_without_keywords_always_runs() {
        let s = CompiledScanner::compile(vec![no_keyword_detector()]).expect("compile");
        let chunk = Chunk {
            data: "id=550e8400-e29b-41d4-a716-446655440000".into(),
            metadata: ChunkMetadata::default(),
        };
        let m = s.scan(&chunk);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].detector_id, "uuid-secret");
    }

    #[test]
    fn scan_emits_multiple_hits_in_one_chunk() {
        let s = CompiledScanner::compile(vec![aws_detector()]).expect("compile");
        let chunk = Chunk {
            data: "AKIA1234567890ABCDEF\nAKIA1234567890ABCDEF\n".into(),
            metadata: ChunkMetadata::default(),
        };
        let m = s.scan(&chunk);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].location.line, Some(1));
        assert_eq!(m[1].location.line, Some(2));
    }

    #[test]
    fn scan_is_empty_when_no_detectors_loaded() {
        let s = CompiledScanner::compile(Vec::new()).expect("empty compile");
        assert!(s.is_empty());
        let chunk = Chunk {
            data: "AKIA1234567890ABCDEF".into(),
            metadata: ChunkMetadata::default(),
        };
        assert!(s.scan(&chunk).is_empty());
    }

    fn twilio_detector_with_required_companion() -> Detector {
        toml::from_str(
            r#"
[detector]
id = "twilio-api-key"
name = "Twilio API Key"
service = "twilio"
severity = "high"
keywords = ["SK"]
[[detector.patterns]]
regex = "SK[a-f0-9]{32}"
[[detector.companions]]
name = "secret"
regex = "(SECRET|secret)[=:\\s\"'']+([a-zA-Z0-9]{32})"
within_lines = 3
required = true
"#,
        )
        .expect("twilio detector parses")
    }

    #[test]
    fn required_companion_blocks_lone_primary() {
        let s = CompiledScanner::compile(vec![twilio_detector_with_required_companion()])
            .expect("compile");
        // Just the SK key on its own — no nearby secret. Detector
        // must NOT fire.
        let chunk = Chunk {
            data: "let twilio_key = \"SKdeadbeefdeadbeefdeadbeefdeadbeef\";".into(),
            metadata: ChunkMetadata::default(),
        };
        assert!(
            s.scan(&chunk).is_empty(),
            "required companion missing — detector must not fire"
        );
    }

    #[test]
    fn required_companion_within_window_fires() {
        let s = CompiledScanner::compile(vec![twilio_detector_with_required_companion()])
            .expect("compile");
        let chunk = Chunk {
            data: "let twilio_key = \"SKdeadbeefdeadbeefdeadbeefdeadbeef\";\nlet secret = \"deadbeefcafebabefeedfacefeebadc0\";".into(),
            metadata: ChunkMetadata::default(),
        };
        let hits = s.scan(&chunk);
        assert_eq!(
            hits.len(),
            1,
            "primary should fire when companion is nearby"
        );
    }

    #[test]
    fn required_companion_outside_window_blocks() {
        let s = CompiledScanner::compile(vec![twilio_detector_with_required_companion()])
            .expect("compile");
        // Companion is present but far away from primary — within_lines
        // = 3 in the fixture; place the companion 10 lines past.
        let mut data = String::from("let twilio_key = \"SKdeadbeefdeadbeefdeadbeefdeadbeef\";\n");
        for _ in 0..10 {
            data.push_str("// filler\n");
        }
        data.push_str("let secret = \"deadbeefcafebabefeedfacefeebadc0\";\n");
        let chunk = Chunk {
            data,
            metadata: ChunkMetadata::default(),
        };
        assert!(
            s.scan(&chunk).is_empty(),
            "companion outside within_lines must not satisfy the requirement"
        );
    }

    #[test]
    fn compile_rejects_invalid_regex() {
        let bad: Detector = toml::from_str(
            r#"
[detector]
id = "bad"
name = "Bad"
service = "s"
severity = "low"
[[detector.patterns]]
regex = "(unbalanced"
"#,
        )
        .expect("parse");
        let r = CompiledScanner::compile(vec![bad]);
        assert!(matches!(r, Err(ScannerError::Regex { detector_id, .. }) if detector_id == "bad"));
    }
}
