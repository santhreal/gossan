//! Wordlist integrity tests.
//!
//! Per GOSSAN_LEGENDARY A10 + B6: every shipped wordlist must:
//!  - have no duplicate entries,
//!  - have no leading `/` (the brute-forcer adds it),
//!  - have no comment lines (those belong in README, not the data file),
//!  - have no blank lines.

use std::collections::HashSet;
use std::path::PathBuf;

const WORDLISTS: &[&str] = &["top-100.txt", "top-1k.txt", "top-10k.txt"];

fn wordlist_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("wordlists");
    p
}

#[test]
fn shipped_wordlists_pass_format_contract() {
    let dir = wordlist_dir();
    for name in WORDLISTS {
        let path = dir.join(name);
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let mut seen = HashSet::new();
        for (i, line) in body.lines().enumerate() {
            let n = i + 1;
            assert!(!line.starts_with('#'), "{name}:{n} contains comment");
            assert!(!line.is_empty(), "{name}:{n} contains blank line");
            assert!(
                !line.starts_with('/'),
                "{name}:{n} starts with `/` (brute-forcer adds it)"
            );
            assert!(
                seen.insert(line.to_string()),
                "{name}:{n} duplicate entry: {line}"
            );
        }
    }
}

#[test]
fn top_100_is_strict_subset_of_top_1k() {
    let dir = wordlist_dir();
    let top100: HashSet<String> = std::fs::read_to_string(dir.join("top-100.txt"))
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let top1k: HashSet<String> = std::fs::read_to_string(dir.join("top-1k.txt"))
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let missing: Vec<&String> = top100.difference(&top1k).collect();
    assert!(
        missing.is_empty(),
        "top-100.txt has entries not in top-1k.txt: {missing:?}"
    );
}
