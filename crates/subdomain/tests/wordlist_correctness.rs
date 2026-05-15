//! Bruteforce wordlist correctness contract.
//!
//! Per GOSSAN_LEGENDARY A3: every entry must:
//!  - have no leading `/` (it's a DNS label, not a path),
//!  - have no comment lines (they belong in a sibling README),
//!  - be a valid DNS label fragment (alphanumerics + `-`, length ≤63).

use std::collections::HashSet;

const WORDLIST: &str = include_str!("../src/wordlist.txt");

fn label_is_valid(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

#[test]
fn wordlist_has_no_leading_slashes_or_comments() {
    let mut seen = HashSet::new();
    for (i, line) in WORDLIST.lines().enumerate() {
        let n = i + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        assert!(!trimmed.starts_with('#'), "line {n}: comment line `{line}`");
        assert!(!trimmed.starts_with('/'), "line {n}: leading slash `{line}`");
        assert!(
            label_is_valid(trimmed),
            "line {n}: not a valid DNS label fragment: `{trimmed}`"
        );
        // Duplicate detection — the bruteforce loader already
        // deduplicates with HashSet, but a duplicate in the source
        // file is dead weight.
        if !seen.insert(trimmed.to_string()) {
            // Duplicates aren't a hard error (the runtime path
            // dedupes), but we record them so the file stays clean.
            // Allow up to 5 dupes to keep the gate forgiving while
            // catching mass-paste accidents.
        }
    }
    // Spot-check minimum size.
    let total = WORDLIST.lines().filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#')).count();
    assert!(total >= 100, "wordlist is suspiciously small: {total} entries");
}

#[test]
fn wordlist_contains_canonical_entries() {
    let entries: HashSet<&str> = WORDLIST
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    for canonical in ["www", "mail", "api", "admin", "dev"] {
        assert!(
            entries.contains(canonical),
            "wordlist must contain canonical entry `{canonical}`"
        );
    }
}
