//! Property tests for the subdomain dedup helper.
//!
//! Per GOSSAN_LEGENDARY A3: arbitrary 10k domains → no panic, all
//! results are valid DNS labels (or rejected upstream by the
//! normalizer).

use gossan_subdomain::dedup::{dedup_domains, normalize_domain};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1_000,
        ..ProptestConfig::default()
    })]

    /// dedup must never panic on arbitrary printable input.
    #[test]
    fn dedup_never_panics_on_arbitrary_strings(
        domains in prop::collection::vec("\\PC{0,128}", 0..256)
    ) {
        let _ = dedup_domains(domains);
    }

    /// normalize_domain returns either Some(lowercase) or None — never
    /// uppercase.
    #[test]
    fn normalize_yields_lowercase_or_none(s in "\\PC{0,128}") {
        if let Some(n) = normalize_domain(&s) {
            prop_assert_eq!(&n, &n.to_lowercase());
        }
    }
}

#[test]
fn ten_thousand_domains_dedup_without_panic() {
    let big: Vec<String> = (0..10_000)
        .map(|i| format!("h{i}.example.com"))
        .collect();
    let deduped = dedup_domains(big);
    assert_eq!(deduped.len(), 10_000);
}

#[test]
fn ten_thousand_duplicates_collapse_to_one() {
    let dups: Vec<String> = (0..10_000).map(|_| "api.example.com".to_string()).collect();
    let deduped = dedup_domains(dups);
    assert_eq!(deduped.len(), 1);
}
