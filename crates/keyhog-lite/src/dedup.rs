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
    /// same secret survive, surface "this token was flagged by both
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

    // ── Boundary: single element ─────────────────────────────────────────

    #[test]
    fn credential_scope_single_element_survives() {
        let v = vec![raw("only-detector", "only-hash")];
        let d = dedup_matches(v, &DedupScope::Credential);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].detector_id, "only-detector");
        assert_eq!(d[0].credential_hash, "only-hash");
    }

    #[test]
    fn detector_and_credential_scope_single_element_survives() {
        let v = vec![raw("det", "h1")];
        let d = dedup_matches(v, &DedupScope::DetectorAndCredential);
        assert_eq!(d.len(), 1);
    }

    // ── Boundary: all identical under Credential scope ───────────────────

    #[test]
    fn credential_scope_collapses_all_identical_to_one() {
        let v = vec![
            raw("det-a", "same-hash"),
            raw("det-b", "same-hash"),
            raw("det-c", "same-hash"),
            raw("det-d", "same-hash"),
        ];
        let d = dedup_matches(v, &DedupScope::Credential);
        assert_eq!(d.len(), 1, "all same hash must collapse to one under Credential scope");
        // First occurrence must win.
        assert_eq!(d[0].detector_id, "det-a");
    }

    // ── Boundary: all distinct under Credential scope ────────────────────

    #[test]
    fn credential_scope_all_distinct_hashes_all_survive() {
        let v: Vec<_> = (0..10).map(|i| raw("det", &format!("hash-{i}"))).collect();
        let d = dedup_matches(v, &DedupScope::Credential);
        assert_eq!(d.len(), 10);
    }

    // ── Anti-rig: DetectorAndCredential preserves per-detector ───────────

    #[test]
    fn detector_and_credential_scope_same_hash_different_detectors_all_survive() {
        let v = vec![
            raw("aws", "hashX"),
            raw("generic-jwt", "hashX"),
            raw("stripe", "hashX"),
        ];
        let d = dedup_matches(v, &DedupScope::DetectorAndCredential);
        assert_eq!(d.len(), 3, "different detectors on same hash must all survive");
        assert_eq!(d[0].detector_id, "aws");
        assert_eq!(d[1].detector_id, "generic-jwt");
        assert_eq!(d[2].detector_id, "stripe");
    }

    #[test]
    fn detector_and_credential_scope_exact_dup_collapses() {
        let v = vec![
            raw("aws", "hashX"),
            raw("aws", "hashX"), // exact dup
            raw("aws", "hashX"), // exact dup
        ];
        let d = dedup_matches(v, &DedupScope::DetectorAndCredential);
        assert_eq!(d.len(), 1, "exact (detector, hash) dup must collapse to one");
    }

    // ── Anti-rig: first-occurrence-wins invariant ────────────────────────

    #[test]
    fn credential_scope_first_occurrence_wins() {
        // Credential scope: all three share same hash → only first survives.
        let v = vec![
            raw("first-detector", "shared-hash"),
            raw("second-detector", "shared-hash"),
            raw("third-detector", "shared-hash"),
        ];
        let d = dedup_matches(v, &DedupScope::Credential);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].detector_id, "first-detector");
    }

    #[test]
    fn detector_and_credential_scope_first_occurrence_wins_per_pair() {
        // Same detector, same hash → first wins; same detector, different hash → both survive.
        let v = vec![
            raw("det", "h1"),
            raw("det", "h1"), // dup
            raw("det", "h2"), // different hash, survives
        ];
        let d = dedup_matches(v, &DedupScope::DetectorAndCredential);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].credential_hash, "h1");
        assert_eq!(d[1].credential_hash, "h2");
    }

    // ── Boundary: empty hash / empty detector_id ─────────────────────────

    #[test]
    fn credential_scope_empty_hash_is_valid_key() {
        let v = vec![raw("det-a", ""), raw("det-b", "")];
        let d = dedup_matches(v, &DedupScope::Credential);
        // Both share the empty-string hash; only first survives.
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].detector_id, "det-a");
    }

    #[test]
    fn detector_and_credential_scope_empty_detector_id_handled() {
        let v = vec![raw("", "h1"), raw("", "h1"), raw("x", "h1")];
        let d = dedup_matches(v, &DedupScope::DetectorAndCredential);
        // ("", "h1") and ("x", "h1") are different keys → 2 survivors.
        assert_eq!(d.len(), 2);
    }

    // ── Stability: large input retains correct count ──────────────────────

    #[test]
    fn credential_scope_large_input_with_alternating_hashes() {
        let v: Vec<_> = (0..200).map(|i| raw("det", &format!("hash-{}", i % 5))).collect();
        let d = dedup_matches(v, &DedupScope::Credential);
        // 5 distinct hashes → exactly 5 survivors (first occurrence of each).
        assert_eq!(d.len(), 5);
        // The first occurrence of hash-0 is index 0.
        assert_eq!(d[0].credential_hash, "hash-0");
    }

    #[test]
    fn detector_and_credential_scope_large_all_unique() {
        let v: Vec<_> = (0..100).map(|i| raw(&format!("det-{i}"), &format!("hash-{i}"))).collect();
        let d = dedup_matches(v, &DedupScope::DetectorAndCredential);
        assert_eq!(d.len(), 100);
    }
}
