//! CPU-only scanner: aho-corasick keyword prefilter + per-detector
//! regex match. Mirrors upstream `keyhog_scanner::CompiledScanner` in
//! shape; no SIMD, no GPU.

use crate::{Detector, Severity};
use aho_corasick::{AhoCorasick, AhoCorasickKind};
use regex::Regex;
use std::collections::HashMap;
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
#[derive(Debug, Clone, Default)]
pub struct Match {
    /// Detector that fired (`aws-access-key`).
    pub detector_id: String,
    /// Detector display name.
    pub detector_name: String,
    /// Service label.
    pub service: String,
    /// Severity carried from the detector.
    pub severity: Severity,
    /// The matched substring (raw (keep out of serialized outputs)).
    pub credential: String,
    /// Captured companion values keyed by companion name. Empty when
    /// the detector has no companions or none matched within window.
    pub companions: HashMap<String, String>,
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

/// Errors raised at compile time. Runtime scan never fails, bad
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
}

struct CompiledCompanion {
    name: Option<String>,
    regex: Regex,
    within_lines: u32,
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
    /// `ScannerError::Regex` and the whole compile aborts, callers
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
                patterns.push(CompiledPattern { regex: re });
            }
            let mut companions = Vec::with_capacity(d.meta.companions.len());
            for c in &d.meta.companions {
                let re = Regex::new(&c.regex).map_err(|e| ScannerError::Regex {
                    detector_id: meta_id.clone(),
                    source: e,
                })?;
                companions.push(CompiledCompanion {
                    name: c.name.clone(),
                    regex: re,
                    within_lines: c.within_lines,
                    required: c.required,
                });
            }

            let keywords: Vec<&String> = d.meta.keywords.iter().filter(|k| !k.is_empty()).collect();
            let keyword_idx_range = if keywords.is_empty() {
                None
            } else {
                let start = all_keywords.len();
                for k in keywords {
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

    /// True when no detectors are loaded, handy in callers that want
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
            for hit in ac.find_overlapping_iter(data) {
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
        // are computed lazily, only when we actually have a hit, walk
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
            // chunk within its `within_lines` window. Companion
            // captures are also returned so the match can carry the
            // co-located public-half of a credential pair.
            for pat in &det.patterns {
                for m in pat.regex.find_iter(data) {
                    // Never emit empty-credential matches, they have no
                    // security value and can be produced by pathological
                    // regexes (e.g. `^$` or `a*`) on empty input.
                    if m.as_str().is_empty() {
                        continue;
                    }
                    if newlines.is_none() {
                        newlines = Some(data.match_indices('\n').map(|(i, _)| i).collect());
                    }
                    let nl = newlines.as_ref().expect("computed above");
                    let line = match nl.binary_search(&m.start()) {
                        Ok(i) | Err(i) => i + 1,
                    };

                    let (required_met, companions) =
                        evaluate_companions(data, nl, line, &det.companions);
                    if !required_met {
                        continue;
                    }

                    // Test-string allowlist: drop matches that smell
                    // like documentation placeholders. Always check
                    // the credential itself; only check the surrounding
                    // line for short, non-minified lines where a
                    // variable name like `TEST_JWT = "eyJ..."` is the
                    // placeholder signal. Long/minified lines may
                    // contain unrelated placeholder words, so we skip
                    // the line-level check there to avoid recall loss.
                    if looks_like_placeholder(m.as_str()) {
                        continue;
                    }
                    let line_text = line_at(data, nl, line);
                    if line_text.len() <= 500 && looks_like_placeholder(line_text) {
                        continue;
                    }

                    out.push(Match {
                        detector_id: det.meta_id.clone(),
                        detector_name: det.meta_name.clone(),
                        service: det.service.clone(),
                        severity: det.severity,
                        credential: m.as_str().to_string(),
                        companions,
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
    // `line` is 1-based. If it's past the last line, return empty.
    if line == 0 || line > newlines.len().saturating_add(1) {
        return "";
    }
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
///: a real secret containing the substring "EXAMPLE" is exotic
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

/// Evaluate all companions against `data` and return two things:
/// - `required_met`: true if every required companion has at least one
///   match within `within_lines` of `primary_line`.
/// - `captures`: a map from companion name to the captured value of the
///   first matching companion within the window. If a companion regex
///   has no capture groups, the full match is stored. Companions without
///   a name are keyed by a unique positional key (`__companion_{idx}`)
///   so an unnamed companion never overwrites an earlier capture. Empty
///   string names are treated the same as missing names. Optional
///   companions are captured too when they match.
fn evaluate_companions(
    data: &str,
    newlines: &[usize],
    primary_line: usize,
    companions: &[CompiledCompanion],
) -> (bool, HashMap<String, String>) {
    let mut required_met = true;
    let mut captures = HashMap::new();
    for (idx, c) in companions.iter().enumerate() {
        let within = c.within_lines as usize;
        let mut matched = false;
        for caps in c.regex.captures_iter(data) {
            let m = caps.get(0).expect("capture 0 always present");
            let comp_line = match newlines.binary_search(&m.start()) {
                Ok(i) | Err(i) => i + 1,
            };
            let distance = if comp_line > primary_line {
                comp_line - primary_line
            } else {
                primary_line - comp_line
            };
            if distance <= within {
                matched = true;
                let value = caps
                    .iter()
                    .skip(1)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .find(|g| g.is_some())
                    .map(|g| g.unwrap().as_str())
                    .unwrap_or_else(|| m.as_str());
                let key = c
                    .name
                    .as_deref()
                    .filter(|n| !n.is_empty())
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| format!("__companion_{idx}"));
                captures.insert(key, value.to_string());
                break;
            }
        }
        if c.required && !matched {
            required_met = false;
        }
    }
    (required_met, captures)
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

    fn unnamed_companions_detector() -> Detector {
        toml::from_str(
            r#"
[detector]
id = "pair"
name = "Pair"
service = "test"
severity = "high"
keywords = ["PAIR"]
[[detector.patterns]]
regex = "PAIR[0-9]{4}"
[[detector.companions]]
regex = "user=(\\S+)"
within_lines = 2
[[detector.companions]]
regex = "pass=(\\S+)"
within_lines = 2
"#,
        )
        .expect("unnamed companions detector parses")
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

    #[test]
    fn unnamed_companions_get_unique_keys() {
        let s = CompiledScanner::compile(vec![unnamed_companions_detector()]).expect("compile");
        let chunk = Chunk {
            data: "PAIR1234\nuser=alice\npass=secret\n".into(),
            metadata: ChunkMetadata::default(),
        };
        let m = s.scan(&chunk);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].companions.len(), 2);
        assert!(!m[0].companions.contains_key(""));
        assert_eq!(m[0].companions.get("__companion_0"), Some(&"alice".to_string()));
        assert_eq!(m[0].companions.get("__companion_1"), Some(&"secret".to_string()));
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
        // Just the SK key on its own, no nearby secret. Detector
        // must NOT fire.
        let chunk = Chunk {
            data: "let twilio_key = \"SKdeadbeefdeadbeefdeadbeefdeadbeef\";".into(),
            metadata: ChunkMetadata::default(),
        };
        assert!(
            s.scan(&chunk).is_empty(),
            "required companion missing, detector must not fire"
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
        // Companion is present but far away from primary, within_lines
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
    fn real_secret_with_placeholder_comment_on_long_line_still_fires() {
        // A real AWS secret whose line also contains a placeholder
        // word in a trailing comment. Because the line is long (>500
        // bytes), the line-level placeholder check is skipped and the
        // secret is still reported.
        let s = CompiledScanner::compile(vec![aws_detector()]).expect("compile");
        let padding = "a".repeat(520);
        let data = format!(
            "const apiKey = \"AKIA1234567890ABCDEF\"; // example placeholder comment {}",
            padding
        );
        let chunk = Chunk {
            data,
            metadata: ChunkMetadata::default(),
        };
        let hits = s.scan(&chunk);
        assert_eq!(hits.len(), 1, "real secret on long placeholder line must fire");
        assert_eq!(hits[0].credential, "AKIA1234567890ABCDEF");
    }

    #[test]
    fn minified_long_line_with_placeholder_word_still_fires() {
        // A minified line longer than 500 bytes contains a placeholder
        // word elsewhere, but the matched secret itself is real. The
        // line-level placeholder suppression must not fire.
        let s = CompiledScanner::compile(vec![aws_detector()]).expect("compile");
        let mut data = String::from("var a=\"AKIA1234567890ABCDEF\",b=\"example\"");
        data.push_str(&";".repeat(500));
        let chunk = Chunk {
            data,
            metadata: ChunkMetadata::default(),
        };
        let hits = s.scan(&chunk);
        assert_eq!(hits.len(), 1, "real secret on minified placeholder line must fire");
        assert_eq!(hits[0].credential, "AKIA1234567890ABCDEF");
    }

    #[test]
    fn required_companion_captured_in_match_companions() {
        // A required companion with a capture group must surface its
        // value on the emitted Match keyed by the companion name.
        let s = CompiledScanner::compile(vec![twilio_detector_with_required_companion()])
            .expect("compile");
        let chunk = Chunk {
            data: "let twilio_key = \"SKdeadbeefdeadbeefdeadbeefdeadbeef\";\nlet secret = \"deadbeefcafebabefeedfacefeebadc0\";".into(),
            metadata: ChunkMetadata::default(),
        };
        let hits = s.scan(&chunk);
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].companions.get("secret"),
            Some(&"deadbeefcafebabefeedfacefeebadc0".to_string()),
            "companion capture must be present on Match"
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

    // ------------------------------------------------------------------
    // Adversarial tests
    // ------------------------------------------------------------------

    #[test]
    fn scan_skips_empty_credential_matches() {
        // A pathological regex that matches the empty string must not
        // produce a finding with an empty credential.
        let det: Detector = toml::from_str(
            r#"
[detector]
id = "empty-match"
name = "Empty Match"
service = "test"
severity = "low"
[[detector.patterns]]
regex = "^$"
"#,
        )
        .expect("parse");
        let scanner = CompiledScanner::compile(vec![det]).expect("compile");
        let chunk = Chunk {
            data: "".into(),
            metadata: ChunkMetadata::default(),
        };
        let matches = scanner.scan(&chunk);
        assert!(
            matches.iter().all(|m| !m.credential.is_empty()),
            "empty credential matches must be filtered out"
        );
        assert!(matches.is_empty());
    }

    #[test]
    fn scan_skips_empty_match_on_nonempty_chunk() {
        let det: Detector = toml::from_str(
            r#"
[detector]
id = "star-match"
name = "Star Match"
service = "test"
severity = "low"
[[detector.patterns]]
regex = "a*"
"#,
        )
        .expect("parse");
        let scanner = CompiledScanner::compile(vec![det]).expect("compile");
        let chunk = Chunk {
            data: "bbb".into(),
            metadata: ChunkMetadata::default(),
        };
        let matches = scanner.scan(&chunk);
        // `a*` matches at every position, including empty matches.
        // All of them must be discarded because the credential is empty.
        assert!(matches.is_empty(), "empty matches must be filtered out");
    }

    #[test]
    fn compile_handles_empty_keywords() {
        // A detector with an empty keyword string must not break the
        // Aho-Corasick prefilter build.
        let det: Detector = toml::from_str(
            r#"
[detector]
id = "empty-kw"
name = "Empty Keyword"
service = "test"
severity = "low"
keywords = [""]
[[detector.patterns]]
regex = "test"
"#,
        )
        .expect("parse");
        let scanner = CompiledScanner::compile(vec![det]).expect("compile");
        let chunk = Chunk {
            data: "this is a test".into(),
            metadata: ChunkMetadata::default(),
        };
        let matches = scanner.scan(&chunk);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].credential, "test");
    }

    #[test]
    fn line_at_zero_line_returns_empty() {
        // Regression: `line_at` used `line - 1` on a usize, which
        // panics in debug mode when `line == 0`.
        let data = "hello\nworld";
        let newlines: Vec<usize> = data.match_indices('\n').map(|(i, _)| i).collect();
        let result = line_at(data, &newlines, 0);
        assert_eq!(result, "");
    }

    #[test]
    fn line_at_past_eof_returns_empty() {
        let data = "hello\nworld";
        let newlines: Vec<usize> = data.match_indices('\n').map(|(i, _)| i).collect();
        assert_eq!(line_at(data, &newlines, 999), "");
    }

    // ------------------------------------------------------------------
    // Proptest property tests
    // ------------------------------------------------------------------

    // ── line_at exact boundary ──────────────────────────────────────────

    #[test]
    fn line_at_first_line_no_newlines() {
        // Single line, no newline char at all.
        let data = "hello world";
        let newlines: Vec<usize> = Vec::new();
        assert_eq!(line_at(data, &newlines, 1), "hello world");
    }

    #[test]
    fn line_at_second_line() {
        let data = "first\nsecond\nthird";
        let newlines: Vec<usize> = data.match_indices('\n').map(|(i, _)| i).collect();
        assert_eq!(line_at(data, &newlines, 2), "second");
    }

    #[test]
    fn line_at_last_line_without_trailing_newline() {
        let data = "a\nb\nc";
        let newlines: Vec<usize> = data.match_indices('\n').map(|(i, _)| i).collect();
        assert_eq!(line_at(data, &newlines, 3), "c");
    }

    #[test]
    fn line_at_line_one_past_eof() {
        // 3-line string has lines 1, 2, 3, line 4 should be empty
        let data = "a\nb\nc";
        let newlines: Vec<usize> = data.match_indices('\n').map(|(i, _)| i).collect();
        assert_eq!(line_at(data, &newlines, 4), "");
    }

    // ── looks_like_placeholder exact matches ─────────────────────────────

    #[test]
    fn looks_like_placeholder_rejects_real_looking_aws_key() {
        // A 20-char key with no placeholder marker (must NOT be filtered).
        assert!(!looks_like_placeholder("AKIA1234567890ABCDEF"));
    }

    #[test]
    fn looks_like_placeholder_catches_xxxxx() {
        assert!(looks_like_placeholder("SKxxxxx123456789012345678901234"));
    }

    #[test]
    fn looks_like_placeholder_catches_not_a_real() {
        assert!(looks_like_placeholder("not_a_real_secret_value"));
    }

    #[test]
    fn looks_like_placeholder_catches_your_underscore() {
        assert!(looks_like_placeholder("your_api_key_here"));
    }

    #[test]
    fn looks_like_placeholder_catches_fakefake() {
        assert!(looks_like_placeholder("fakefakefakefakefakefakefakefake"));
    }

    #[test]
    fn looks_like_placeholder_catches_dummy() {
        assert!(looks_like_placeholder("dummy_token_goes_here"));
    }

    // ── companion within_lines exact boundary ────────────────────────────

    #[test]
    fn companion_exactly_at_within_lines_boundary_fires() {
        // within_lines = 3; companion exactly 3 lines away must fire.
        let det: Detector = toml::from_str(r#"
[detector]
id = "boundary-test"
name = "Boundary Test"
service = "test"
severity = "high"
keywords = ["SK"]
[[detector.patterns]]
regex = "SK[a-f0-9]{32}"
[[detector.companions]]
regex = "SECRET=[a-zA-Z0-9]{32}"
within_lines = 3
required = true
"#).expect("parse");
        let scanner = CompiledScanner::compile(vec![det]).expect("compile");
        // primary on line 1, companion on line 4 (exactly 3 lines apart)
        let data = "let key = \"SKdeadbeefdeadbeefdeadbeefdeadbeef\";\n// filler\n// filler\nSECRET=deadbeefcafebabefeedfacefeebadc0\n";
        let chunk = Chunk { data: data.into(), metadata: ChunkMetadata::default() };
        let hits = scanner.scan(&chunk);
        assert_eq!(hits.len(), 1, "companion at exactly within_lines=3 must fire");
    }

    #[test]
    fn companion_one_past_within_lines_boundary_blocks() {
        // within_lines = 3; companion exactly 4 lines away must NOT fire.
        let det: Detector = toml::from_str(r#"
[detector]
id = "boundary-test-2"
name = "Boundary Test 2"
service = "test"
severity = "high"
keywords = ["SK"]
[[detector.patterns]]
regex = "SK[a-f0-9]{32}"
[[detector.companions]]
regex = "SECRET=[a-zA-Z0-9]{32}"
within_lines = 3
required = true
"#).expect("parse");
        let scanner = CompiledScanner::compile(vec![det]).expect("compile");
        // primary line 1, companion line 5 → distance 4 > within_lines=3
        let data = "let key = \"SKdeadbeefdeadbeefdeadbeefdeadbeef\";\n// l2\n// l3\n// l4\nSECRET=deadbeefcafebabefeedfacefeebadc0\n";
        let chunk = Chunk { data: data.into(), metadata: ChunkMetadata::default() };
        let hits = scanner.scan(&chunk);
        assert!(hits.is_empty(), "companion 4 lines away must not fire when within_lines=3");
    }

    // ── scan with empty chunk data ───────────────────────────────────────

    #[test]
    fn scan_empty_chunk_data_returns_empty() {
        let s = CompiledScanner::compile(vec![aws_detector()]).expect("compile");
        let chunk = Chunk { data: "".into(), metadata: ChunkMetadata::default() };
        assert!(s.scan(&chunk).is_empty());
    }

    // ── metadata propagation ─────────────────────────────────────────────

    #[test]
    fn scan_propagates_commit_and_author_to_match_location() {
        let s = CompiledScanner::compile(vec![aws_detector()]).expect("compile");
        let chunk = Chunk {
            data: "AKIA1234567890ABCDEF".into(),
            metadata: ChunkMetadata {
                source_type: "scm".into(),
                path: Some("secrets.txt".into()),
                commit: Some("abc123def456".into()),
                author: Some("alice@example.com".into()),
                date: Some("2024-01-01".into()),
            },
        };
        let hits = s.scan(&chunk);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].location.commit.as_deref(), Some("abc123def456"));
        assert_eq!(hits[0].location.author.as_deref(), Some("alice@example.com"));
        assert_eq!(hits[0].location.date.as_deref(), Some("2024-01-01"));
        assert_eq!(hits[0].location.source, "scm");
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn line_at_never_panics(data in "[a-zA-Z0-9]{0,200}", line in 0usize..500usize) {
            let newlines: Vec<usize> = data.match_indices('\n').map(|(i, _)| i).collect();
            let _ = line_at(&data, &newlines, line);
        }

        #[test]
        fn looks_like_placeholder_never_panics(s in "\\PC*") {
            let _ = looks_like_placeholder(&s);
        }

        #[test]
        fn compile_empty_detector_list_always_succeeds(_dummy in Just(())) {
            let scanner = CompiledScanner::compile(Vec::new());
            prop_assert!(scanner.is_ok());
            prop_assert!(scanner.unwrap().is_empty());
        }
    }
}
