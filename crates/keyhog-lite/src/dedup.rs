//! Match dedup. Mirrors upstream's behaviour: collapse matches that
//! refer to the same secret to avoid emitting one finding per pattern
//! that fires.

use crate::verifier::RawMatch;
use std::collections::HashSet;

/// Granularity of dedup keying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupScope {
    /// Dedup by credential hash alone. Two matches of the same secret
    /// at different offsets collapse into one. This is the default for
    /// gossan-js / gossan-scm.
    Credential,
    /// Dedup by (detector, credential). Different detectors for the
    /// same secret survive — surface "this token was flagged by both
    /// the AWS rule and the generic-jwt rule".
    DetectorAndCredential,
}

/// Dedup a list of `RawMatch` per scope. Stable order: first occurrence
/// wins.
#[must_use]
pub fn dedup_matches(matches: Vec<RawMatch>, scope: &DedupScope) -> Vec<RawMatch> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::with_capacity(matches.len());
    for m in matches {
        let key = match scope {
            DedupScope::Credential => m.credential_hash.clone(),
            DedupScope::DetectorAndCredential => {
                format!("{}|{}", m.detector_id, m.credential_hash)
            }
        };
        if seen.insert(key) {
            out.push(m);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::MatchLocation;
    use crate::Severity;
    use std::collections::HashMap;

    fn raw(detector_id: &str, credential_hash: &str) -> RawMatch {
        RawMatch {
            detector_id: detector_id.into(),
            detector_name: detector_id.into(),
            service: detector_id.into(),
            severity: Severity::High,
            credential: "raw".into(),
            credential_hash: credential_hash.into(),
            companions: HashMap::new(),
            location: MatchLocation::default(),
            entropy: None,
            confidence: Some(1.0),
        }
    }

    #[test]
    fn credential_scope_collapses_same_hash_across_detectors() {
        let v = vec![
            raw("aws", "hashA"),
            raw("generic-jwt", "hashA"),
            raw("aws", "hashB"),
        ];
        let d = dedup_matches(v, &DedupScope::Credential);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].detector_id, "aws");
        assert_eq!(d[1].detector_id, "aws");
        assert_eq!(d[1].credential_hash, "hashB");
    }

    #[test]
    fn detector_and_credential_scope_preserves_per_detector() {
        let v = vec![
            raw("aws", "hashA"),
            raw("generic-jwt", "hashA"),
            raw("aws", "hashA"), // exact dup
        ];
        let d = dedup_matches(v, &DedupScope::DetectorAndCredential);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].detector_id, "aws");
        assert_eq!(d[1].detector_id, "generic-jwt");
    }

    #[test]
    fn dedup_empty_input_returns_empty() {
        let d = dedup_matches(Vec::new(), &DedupScope::Credential);
        assert!(d.is_empty());
    }

    #[test]
    fn dedup_preserves_insertion_order_for_unique_keys() {
        let v = vec![raw("a", "h1"), raw("b", "h2"), raw("c", "h3")];
        let d = dedup_matches(v, &DedupScope::Credential);
        assert_eq!(d.len(), 3);
        assert_eq!(d[0].detector_id, "a");
        assert_eq!(d[1].detector_id, "b");
        assert_eq!(d[2].detector_id, "c");
    }
}
