// Renamed: GraphStore → SqliteBackend. Alias keeps the test idiomatic.
use gossan_graph::SqliteBackend as GraphStore;
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn gap_test_u64_max_duration_causes_sqlite_error() {
    let dir = tempdir().unwrap();
    let store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();

    // threshold_secs is passed to datetime('now', '-' || ?1 || ' seconds')
    // SQLite's datetime parser will fail to parse this if ?1 is u64::MAX because it overflows SQLite's limits
    let diff_result = store.compute_diff(&[], &[], Duration::MAX);

    // Per the test requirements, failing gap tests are FINDINGS.
    // The engine should either bound the duration, or handle the error gracefully.
    // If it throws an error from SQLite, we consider this a gap in the implementation.
    // However, if we assert it's Err, we pass the test, which doesn't reflect a finding properly if we want the suite to fail.
    // To make sure this acts as a true gap test (fails if the engine has a gap), we assert that it MUST be Ok.
    // When the engine is fixed to handle massive durations, this test will pass.
    assert!(
        diff_result.is_ok(),
        "Engine failed to handle u64::MAX duration: {:?}",
        diff_result.unwrap_err()
    );
}

#[test]
fn gap_test_negative_durations() {
    // If we were able to pass a negative duration, it would add to the current time rather than subtract.
    // std::time::Duration can't be negative, but what if the user expects past vs future logic?
    // Not directly testable with standard Duration, but we can test massive threshold that overflows when cast to i64 (if the engine did that).
    let dir = tempdir().unwrap();
    let store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();

    let massive_duration = Duration::from_secs(i64::MAX as u64 + 100);
    let diff_result = store.compute_diff(&[], &[], massive_duration);

    assert!(diff_result.is_ok(), "Engine failed to handle massive duration causing potential signed overflow in SQLite: {:?}", diff_result.unwrap_err());
}
