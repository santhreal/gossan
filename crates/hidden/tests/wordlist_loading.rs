//! Wordlist Tier B loading test for `gossan-hidden::directory_brute`.
//!
//! Per GOSSAN_LEGENDARY A10: load custom wordlist from path; assert
//! the loader uses it when set, falls back to default otherwise.

use gossan_hidden::directory_brute::load_wordlist;
use std::io::Write;

#[test]
fn custom_wordlist_path_overrides_builtin() {
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    writeln!(f, "# header comment, must be stripped").unwrap();
    writeln!(f, "alpha").unwrap();
    writeln!(f, "beta").unwrap();
    writeln!(f, "/gamma").unwrap(); // leading slash should be stripped
    writeln!(f, "alpha").unwrap(); // duplicate, should dedup
    writeln!(f).unwrap();
    f.flush().unwrap();

    let path = f.path().to_string_lossy().into_owned();
    let words = load_wordlist(Some(&path));
    // The 4 unique entries minus the comment minus the blank.
    assert!(words.contains(&"alpha".to_string()));
    assert!(words.contains(&"beta".to_string()));
    assert!(
        words.contains(&"gamma".to_string()),
        "leading-slash entry must be stripped to bare label; got {words:?}"
    );
    assert!(
        !words.iter().any(|w| w.starts_with('#')),
        "comment lines must be stripped"
    );
    let mut unique = words.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), words.len(), "loader must dedup");
}

#[test]
fn missing_custom_path_falls_back_to_builtin() {
    let words = load_wordlist(Some("/nonexistent/path/to/wordlist"));
    assert!(
        !words.is_empty(),
        "missing custom wordlist must fall back to builtin (non-empty)"
    );
}

#[test]
fn no_custom_path_returns_builtin() {
    let words = load_wordlist(None);
    assert!(
        !words.is_empty(),
        "no custom path must return builtin (non-empty)"
    );
}
