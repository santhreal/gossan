//! Subdomain Tier-B list loading  -  a thin delegate to the single
//! shared `gossan_core::tierb` loader (M5 consolidation). This file no
//! longer carries loader logic; it only pins the subdomain-specific
//! repo dev root and keeps the `load(embedded, kind, custom)` shape
//! that `bruteforce` / `permutations` already call.

use std::path::PathBuf;

/// Load a subdomain Tier-B list (bruteforce labels / permutation
/// patterns). `embedded` is the compiled-in baseline; `kind` is the
/// drop-in subdir (`"subdomains"` / `"permutations"`); `custom` is an
/// explicit operator override that replaces the default.
#[must_use]
pub fn load(embedded: &str, kind: &str, custom: Option<&str>) -> Vec<String> {
    gossan_core::tierb::load_wordlist(
        &[embedded],
        kind,
        custom,
        // Repo/dev root so a `cargo run` from the workspace also sees
        // the shipped `wordlists/` (which is otherwise a drop-in dir).
        &[PathBuf::from("crates/subdomain/wordlists")],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegates_with_embedded_floor() {
        // No drop-ins reachable for this synthetic kind: the embedded
        // baseline is the floor (delegation wired correctly).
        let w = load("api\ndev\napi\n", "subdomains-none-xyz", None);
        assert!(w.contains(&"api".to_string()) && w.contains(&"dev".to_string()));
        assert_eq!(w.iter().filter(|x| *x == "api").count(), 1, "deduped via core");
    }

    #[test]
    fn custom_replaces_via_core() {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), "only\n").unwrap();
        assert_eq!(
            load("api\ndev\n", "subdomains", Some(&f.path().to_string_lossy())),
            vec!["only"]
        );
    }
}
