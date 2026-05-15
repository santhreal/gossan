//! Detector TOML schema + loader.
//!
//! Mirrors the on-disk format used by `software/keyhog/detectors/*.toml`
//! so this crate can load the same files without modification.

use crate::Severity;
use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

/// One detector — corresponds 1:1 with a `[detector]` block in TOML.
#[derive(Debug, Clone, Deserialize)]
pub struct Detector {
    /// The `[detector]` block.
    #[serde(rename = "detector")]
    pub meta: DetectorMeta,
}

/// Metadata + match config for a single detector.
#[derive(Debug, Clone, Deserialize)]
pub struct DetectorMeta {
    /// Stable identifier (`aws-access-key`).
    pub id: String,
    /// Human-readable name (`AWS Access Key`).
    pub name: String,
    /// Service / provider label (`aws`, `stripe`, …).
    pub service: String,
    /// Severity for findings emitted by this detector.
    pub severity: Severity,
    /// Aho-Corasick keywords used for the prefilter. Empty = run regex
    /// scan directly.
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Required patterns (any one must match for the detector to fire).
    #[serde(default, rename = "patterns")]
    pub patterns: Vec<Pattern>,
    /// Optional companion patterns. When present, the verifier may use
    /// them to elevate severity; this slice records them but does not
    /// run live verification.
    #[serde(default, rename = "companions")]
    pub companions: Vec<Companion>,
}

/// A required regex pattern.
#[derive(Debug, Clone, Deserialize)]
pub struct Pattern {
    /// The regex. Compiled lazily inside `CompiledScanner::compile`.
    pub regex: String,
    /// Free-form description used in findings.
    #[serde(default)]
    pub description: String,
}

fn default_within_lines() -> u32 {
    5
}

/// A companion (co-located) pattern.
#[derive(Debug, Clone, Deserialize)]
pub struct Companion {
    /// Regex pattern.
    pub regex: String,
    /// How far away (in source lines) the companion must appear.
    #[serde(default = "default_within_lines")]
    pub within_lines: u32,
    /// Optional companion name.
    #[serde(default)]
    pub name: Option<String>,
    /// If true, the detector MUST NOT fire unless this companion is
    /// also found within `within_lines` of the primary match. Used by
    /// providers like Twilio / Stripe / Avalara where the secret-side
    /// of the credential is the strong signal — finding the public
    /// `SK...` ID alone is too noisy on its own to report.
    #[serde(default)]
    pub required: bool,
}

/// Errors raised by the TOML loader. `Other` covers `io::Error` and any
/// downstream errors we don't want to expose by concrete type so the
/// public surface stays stable across upstream schema bumps.
#[derive(Debug, Error)]
pub enum DetectorError {
    /// The detector directory was not found at the supplied path.
    #[error("detector directory not found: {0}")]
    DirNotFound(String),
    /// A specific TOML file failed to parse. Other files in the
    /// directory are still loaded — see `load_detectors` for the
    /// best-effort semantics.
    #[error("parse error in {path}: {source}")]
    Parse {
        /// Path of the malformed file.
        path: String,
        /// Underlying serde / toml error.
        #[source]
        source: toml::de::Error,
    },
    /// An I/O failure that the loader couldn't recover from.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Load every `*.toml` in `dir` as a detector. Files that fail to parse
/// are skipped with a `tracing::warn` — a single malformed contribution
/// MUST NOT block the rest of the scan. Returns an error only when the
/// directory itself is missing.
pub fn load_detectors(dir: &Path) -> Result<Vec<Detector>, DetectorError> {
    if !dir.exists() {
        return Err(DetectorError::DirNotFound(dir.display().to_string()));
    }
    let mut out = Vec::new();
    let read = std::fs::read_dir(dir)?;
    for entry in read.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(s) => match toml::from_str::<Detector>(&s) {
                Ok(d) => out.push(d),
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        err = %e,
                        "keyhog-lite: skipping malformed detector"
                    );
                }
            },
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    err = %e,
                    "keyhog-lite: failed to read detector file"
                );
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write(path: &std::path::Path, contents: &str) {
        let mut f = std::fs::File::create(path).expect("write fixture");
        f.write_all(contents.as_bytes()).expect("write fixture");
    }

    #[test]
    fn load_detectors_parses_a_minimal_detector() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        write(
            &tmp.path().join("aws.toml"),
            r#"
[detector]
id = "aws-access-key"
name = "AWS Access Key"
service = "aws"
severity = "critical"
keywords = ["AKIA"]

[[detector.patterns]]
regex = "AKIA[0-9A-Z]{16}"
description = "AWS AKIA prefix"
"#,
        );
        let detectors = load_detectors(tmp.path()).expect("load");
        assert_eq!(detectors.len(), 1);
        assert_eq!(detectors[0].meta.id, "aws-access-key");
        assert_eq!(detectors[0].meta.severity, Severity::Critical);
        assert_eq!(detectors[0].meta.keywords, vec!["AKIA"]);
        assert_eq!(detectors[0].meta.patterns.len(), 1);
    }

    #[test]
    fn load_detectors_skips_malformed_and_keeps_valid() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        write(&tmp.path().join("good.toml"), r#"
[detector]
id = "good"
name = "Good"
service = "test"
severity = "high"
[[detector.patterns]]
regex = "foo"
"#);
        write(&tmp.path().join("bad.toml"), "this is not [[ valid toml");
        let detectors = load_detectors(tmp.path()).expect("load");
        assert_eq!(detectors.len(), 1);
        assert_eq!(detectors[0].meta.id, "good");
    }

    #[test]
    fn load_detectors_errors_on_missing_dir() {
        let r = load_detectors(std::path::Path::new("/nonexistent/keyhog/detectors"));
        assert!(matches!(r, Err(DetectorError::DirNotFound(_))));
    }

    #[test]
    fn load_detectors_ignores_non_toml_files() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        write(&tmp.path().join("README.md"), "# detectors");
        write(&tmp.path().join("notes.txt"), "ignore me");
        write(
            &tmp.path().join("d.toml"),
            r#"
[detector]
id = "d"
name = "D"
service = "test"
severity = "low"
[[detector.patterns]]
regex = "x"
"#,
        );
        let detectors = load_detectors(tmp.path()).expect("load");
        assert_eq!(detectors.len(), 1);
    }

    #[test]
    fn companion_default_within_lines_is_5() {
        let toml = r#"
[detector]
id = "x"
name = "X"
service = "s"
severity = "info"
[[detector.patterns]]
regex = "a"
[[detector.companions]]
regex = "b"
"#;
        let d: Detector = toml::from_str(toml).expect("parse");
        assert_eq!(d.meta.companions.len(), 1);
        assert_eq!(d.meta.companions[0].within_lines, 5);
    }
}
