//! One shared Tier-B list loader for the whole workspace.
//!
//! CLAUDE.md two-tier config: Tier-B is community knowledge shipped as
//! drop-in data, the moat clones cannot copy. This module is the SINGLE
//! implementation (M5 consolidation)  -  `gossan-hidden` (content-
//! discovery wordlists) and `gossan-subdomain` (bruteforce labels +
//! permutation patterns) had near-identical copies; both now delegate
//! here. New Tier-B consumers call this; they do not reimplement it.
//!
//! Semantics (recall-first):
//! * explicit `custom` path → **replace** (the operator asked for
//!   exactly that list  -  ffuf/puredns `-w` parity);
//! * otherwise: the union of every compiled-in `embedded` baseline
//!   (a slice  -  some consumers ship two largely-disjoint sets) plus
//!   every community `*.txt` dropped under a resolved Tier-B root.
//!   Drop-ins **extend**, never shadow (a tiny research file must not
//!   delete the embedded baseline). The baseline is embedded, so an
//!   installed binary works with zero filesystem dependency.

use std::collections::HashSet;
use std::path::PathBuf;

use serde::Deserialize;

/// A parse strategy: trim/comment/dedup is shared; whether the token
/// is normalized (case/slash) is the axis that differs. A `fn` pointer
/// (not a generic) keeps `load_lines`/`load_wordlist` monomorphic and
/// the file-walking core a single instantiation.
type ParseFn = fn(&str, &mut HashSet<String>, &mut Vec<String>);

/// **Generic** line parse: trim, drop blank + `#` comments, dedup
/// (order-preserving) via the shared `seen` set. The token is kept
/// **verbatim**  -  NO lowercasing, NO leading-`/` strip. Correct for
/// anything case/slash-significant: regex patterns, header names,
/// signatures. This is the floor `parse_wordlist` builds on.
fn parse_lines(content: &str, seen: &mut HashSet<String>, sink: &mut Vec<String>) {
    for line in content.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if seen.insert(l.to_string()) {
            sink.push(l.to_string());
        }
    }
}

/// **Wordlist** parse: `parse_lines` semantics PLUS DNS-label / URL-
/// path normalization  -  strip a leading `/` (callers concatenate;
/// these are not absolute) and lowercase (hostnames and path brute
/// are case-insensitive, so `/API` and `api` are one entry). This is
/// WRONG for regex/case-significant data  -  those use [`load_lines`].
fn parse_wordlist(content: &str, seen: &mut HashSet<String>, sink: &mut Vec<String>) {
    for line in content.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let l = l.strip_prefix('/').unwrap_or(l).to_lowercase();
        if !l.is_empty() && seen.insert(l.clone()) {
            sink.push(l);
        }
    }
}

/// Generic Tier-B roots for `kind` (e.g. `"wordlists"`,
/// `"subdomains"`, `"permutations"`), resolved so an **installed**
/// binary finds them  -  not a CWD-relative path (the bug M1 fixed).
/// Precedence: `$GOSSAN_RULES_DIR`, alongside the executable, a
/// generic CWD `rules/<kind>`, then any caller-supplied `extra` dev
/// roots (repo paths a crate knows about). First match does not win  - 
/// ALL existing roots are unioned.
fn roots(kind: &str, extra: &[PathBuf]) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(d) = std::env::var("GOSSAN_RULES_DIR") {
        let d = PathBuf::from(d);
        v.push(d.join(kind));
        v.push(d);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            v.push(dir.join("rules").join(kind));
            v.push(dir.join(kind));
        }
    }
    v.push(PathBuf::from("rules").join(kind));
    v.extend_from_slice(extra);
    v
}

/// Every existing Tier-B drop-in file with extension `ext` under any
/// resolved root for `kind`. Public so NON-line consumers reuse the
/// SAME robust root resolution instead of reimplementing it (M5
/// single-source doctrine): `gossan-classify` ships TOML rule packs
/// and does its own serde, but discovers the files through here, so a
/// `$GOSSAN_RULES_DIR` / next-to-binary / repo-dev drop works
/// identically for line lists and structured packs alike.
#[must_use]
pub fn dropin_files(kind: &str, extra_roots: &[PathBuf], ext: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for root in roots(kind, extra_roots) {
        if let Ok(rd) = std::fs::read_dir(&root) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.extension().and_then(|x| x.to_str()) == Some(ext) {
                    out.push(p);
                }
            }
        }
    }
    out
}

/// Load a Tier-B list under a chosen parse strategy. `embedded` is the
/// compiled-in baseline(s)  -  the recall floor, unioned in order;
/// `kind` selects the drop-in subdir; `custom` is an explicit operator
/// override that REPLACES the default; `extra_roots` are crate-
/// specific dev/repo dirs to also scan.
fn load_with(
    parse: ParseFn,
    embedded: &[&str],
    kind: &str,
    custom: Option<&str>,
    extra_roots: &[PathBuf],
) -> Vec<String> {
    if let Some(path) = custom {
        if let Ok(c) = std::fs::read_to_string(path) {
            let mut seen = HashSet::new();
            let mut out = Vec::new();
            parse(&c, &mut seen, &mut out);
            if !out.is_empty() {
                tracing::info!(count = out.len(), path, kind, "custom Tier-B list (replaces default)");
                return out;
            }
        }
        tracing::warn!(path, kind, "custom Tier-B list unreadable/empty  -  using default union");
    }

    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for e in embedded {
        parse(e, &mut seen, &mut out);
    }
    let base = out.len();
    let mut drop_in_files = 0usize;
    for p in dropin_files(kind, extra_roots, "txt") {
        if let Ok(c) = std::fs::read_to_string(&p) {
            let before = out.len();
            parse(&c, &mut seen, &mut out);
            if out.len() > before {
                drop_in_files += 1;
            }
        }
    }
    tracing::info!(
        total = out.len(),
        embedded = base,
        drop_in_files,
        kind,
        "Tier-B list (embedded baseline ∪ drop-ins)"
    );
    out
}

/// Load a Tier-B **wordlist** (DNS labels / URL-path brute tokens):
/// trim/comment/dedup + lowercase + leading-`/` strip. Used by
/// `gossan-hidden` content discovery and `gossan-subdomain`
/// bruteforce/permutations. See [`load_with`] for the union/replace
/// semantics.
#[must_use]
pub fn load_wordlist(
    embedded: &[&str],
    kind: &str,
    custom: Option<&str>,
    extra_roots: &[PathBuf],
) -> Vec<String> {
    load_with(parse_wordlist, embedded, kind, custom, extra_roots)
}

/// Load a Tier-B **verbatim line list** (regex patterns, header
/// names, signatures  -  anything case/slash-significant): trim/comment/
/// dedup ONLY, token kept exactly as written. Used by `gossan-js`
/// endpoint-extraction patterns. Same union/replace semantics as
/// [`load_wordlist`]; the ONLY difference is no token normalization.
#[must_use]
pub fn load_lines(
    embedded: &[&str],
    kind: &str,
    custom: Option<&str>,
    extra_roots: &[PathBuf],
) -> Vec<String> {
    load_with(parse_lines, embedded, kind, custom, extra_roots)
}

/// TOML schema for Tier-B wordlist fragments (M1).
/// Supports `words = [".."]` and `[[entry]] value = ".." ` / [[path]] etc.
/// Drop-ins *.toml under kind/ are unioned.
#[derive(Debug, Default, Deserialize)]
struct WordlistToml {
    #[serde(default)]
    words: Vec<String>,
    #[serde(default)]
    entry: Vec<WordEntry>,
    #[serde(default)]
    path: Vec<WordEntry>,
}

#[derive(Debug, Deserialize)]
struct WordEntry {
    #[serde(alias = "value", alias = "path", alias = "entry")]
    value: String,
}

/// Load wordlist from TOML (M1). Embedded = raw toml strings from include_str of rules/wordlists/*.toml .
/// Also loads .txt dropins for compat. Custom replaces.
#[must_use]
pub fn load_wordlist_toml(
    embedded: &[&str],
    kind: &str,
    custom: Option<&str>,
    extra_roots: &[PathBuf],
) -> Vec<String> {
    if let Some(path) = custom {
        if let Ok(c) = std::fs::read_to_string(path) {
            let mut seen = HashSet::new();
            let mut out = Vec::new();
            parse_wordlist(&c, &mut seen, &mut out);
            if !out.is_empty() {
                tracing::info!(count = out.len(), path, kind, "custom Tier-B list (replaces default)");
                return out;
            }
        }
        tracing::warn!(path, kind, "custom Tier-B list unreadable/empty  -  using default union");
    }

    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for e in embedded {
        if let Ok(parsed) = toml::from_str::<WordlistToml>(e) {
            for w in &parsed.words {
                let l = w.trim().strip_prefix('/').unwrap_or(w).to_lowercase();
                if !l.is_empty() && seen.insert(l.clone()) { out.push(l); }
            }
            for ent in parsed.entry.iter().chain(&parsed.path) {
                let w = &ent.value;
                let l = w.trim().strip_prefix('/').unwrap_or(w).to_lowercase();
                if !l.is_empty() && seen.insert(l.clone()) { out.push(l); }
            }
        }
    }
    let base = out.len();
    let mut drop_in_files = 0usize;
    for ext in ["toml", "txt"] {
        for p in dropin_files(kind, extra_roots, ext) {
            if let Ok(c) = std::fs::read_to_string(&p) {
                let before = out.len();
                if ext == "toml" {
                    if let Ok(parsed) = toml::from_str::<WordlistToml>(&c) {
                        for w in &parsed.words {
                            let l = w.trim().strip_prefix('/').unwrap_or(w).to_lowercase();
                            if !l.is_empty() && seen.insert(l.clone()) { out.push(l); }
                        }
                        for ent in parsed.entry.iter().chain(&parsed.path) {
                            let w = &ent.value;
                            let l = w.trim().strip_prefix('/').unwrap_or(w).to_lowercase();
                            if !l.is_empty() && seen.insert(l.clone()) { out.push(l); }
                        }
                    }
                } else {
                    parse_wordlist(&c, &mut seen, &mut out);
                }
                if out.len() > before { drop_in_files += 1; }
            }
        }
    }
    tracing::info!(total = out.len(), embedded = base, drop_in_files, kind, "Tier-B wordlist (toml baseline ∪ drop-ins)");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "# c\n/api\nDEV\napi\n\n";
    const B: &str = "staging\nDEV\nvpn\n"; // overlaps A on dev

    #[test]
    fn parse_wordlist_strips_comment_slash_case_and_dedups() {
        let mut s = HashSet::new();
        let mut o = Vec::new();
        parse_wordlist(A, &mut s, &mut o);
        assert_eq!(o, vec!["api", "dev"], "got {o:?}");
    }

    /// The M3 design correction: `parse_lines` keeps the token
    /// VERBATIM (no lowercase, no leading-`/` strip). A regex pattern
    /// run through `parse_wordlist` is silently corrupted  -  this is
    /// the test that fails if the two ever collapse back into one.
    #[test]
    fn parse_lines_preserves_case_and_slash_unlike_wordlist() {
        // A real JS-endpoint regex: leading `["'`]`, an alternation
        // with uppercase, an absolute `/` inside a class. Lowercasing
        // or `/`-stripping it changes what it matches.
        let rx = r#"["'`](/(?:api|Admin|GraphQL)[^"'`\s]{0,200})["'`]"#;
        let src = format!("# js endpoint patterns\n{rx}\n{rx}\n");

        let mut s = HashSet::new();
        let mut verbatim = Vec::new();
        parse_lines(&src, &mut s, &mut verbatim);
        assert_eq!(verbatim, vec![rx.to_string()], "lines: verbatim + deduped");

        let mut s2 = HashSet::new();
        let mut mangled = Vec::new();
        parse_wordlist(&src, &mut s2, &mut mangled);
        assert_ne!(
            mangled, verbatim,
            "wordlist parse MUST corrupt a regex (proves the split is load-bearing)"
        );
        assert!(
            mangled[0].contains("admin") && mangled[0].contains("graphql"),
            "wordlist parse lowercased the alternation: {:?}",
            mangled[0]
        );
    }

    #[test]
    fn multi_embedded_unions_and_dedups_cross_set() {
        let w = load_wordlist(&[A, B], "kind-xyz-none", None, &[]);
        assert!(w.contains(&"api".to_string()));
        assert!(w.contains(&"staging".to_string()));
        assert!(w.contains(&"vpn".to_string()));
        // `dev` is in BOTH A and B  -  must appear exactly once.
        assert_eq!(w.iter().filter(|x| *x == "dev").count(), 1, "cross-set dedup");
    }

    #[test]
    fn embedded_is_the_floor_with_no_dropins() {
        let w = load_wordlist(&[A], "definitely-no-such-kind-zzz", None, &[]);
        assert!(w.contains(&"api".to_string()) && w.len() >= 2);
    }

    #[test]
    fn custom_path_replaces_all_embedded() {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), "only-this\nonly-this\n").unwrap();
        let w = load_wordlist(&[A, B], "k", Some(&f.path().to_string_lossy()), &[]);
        assert_eq!(w, vec!["only-this"], "explicit list REPLACES, deduped");
    }

    #[test]
    fn dropped_file_extends_without_shadowing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("wl")).unwrap();
        std::fs::write(dir.path().join("wl").join("x.txt"), "zzz-core-tierb-sentinel\n").unwrap();
        std::env::set_var("GOSSAN_RULES_DIR", dir.path());
        let w = load_wordlist(&[A], "wl", None, &[]);
        std::env::remove_var("GOSSAN_RULES_DIR");
        assert!(w.iter().any(|x| x == "zzz-core-tierb-sentinel"), "drop-in extends");
        assert!(w.contains(&"api".to_string()), "drop-in must NOT shadow embedded");
    }

    /// `dropin_files` is the shared discovery non-line consumers
    /// (classify TOML packs) reuse: it must find files by the
    /// requested extension under a resolved root, and NOT mix
    /// extensions (a `.toml` pack must not pick up a `.txt` wordlist
    /// sitting in the same dir).
    #[test]
    fn dropin_files_discovers_by_extension_under_resolved_root() {
        let dir = tempfile::tempdir().unwrap();
        let kd = dir.path().join("packs");
        std::fs::create_dir_all(&kd).unwrap();
        std::fs::write(kd.join("a.toml"), "x=1\n").unwrap();
        std::fs::write(kd.join("b.toml"), "y=2\n").unwrap();
        std::fs::write(kd.join("note.txt"), "ignore me\n").unwrap();
        std::env::set_var("GOSSAN_RULES_DIR", dir.path());
        let toml = dropin_files("packs", &[], "toml");
        std::env::remove_var("GOSSAN_RULES_DIR");
        assert_eq!(toml.len(), 2, "two .toml found, .txt excluded: {toml:?}");
        assert!(toml.iter().all(|p| p.extension().unwrap() == "toml"));
    }

    /// `load_lines` end-to-end: a JS-regex baseline ∪ a community
    /// drop-in survives with case + slashes intact, deduped.
    #[test]
    fn load_lines_unions_verbatim_patterns() {
        let base = r#"fetch\(["'`]([^"'`\s]{1,200})["'`]"#;
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("js-endpoints")).unwrap();
        std::fs::write(
            dir.path().join("js-endpoints").join("extra.txt"),
            "# community pattern\n\\.AjaxCall\\(\"(/[A-Z][^\"]+)\"\n",
        )
        .unwrap();
        std::env::set_var("GOSSAN_RULES_DIR", dir.path());
        let w = load_lines(&[base], "js-endpoints", None, &[]);
        std::env::remove_var("GOSSAN_RULES_DIR");
        assert!(w.contains(&base.to_string()), "embedded regex verbatim");
        assert!(
            w.iter().any(|p| p == r#"\.AjaxCall\("(/[A-Z][^"]+)""#),
            "drop-in regex verbatim (uppercase + `/` intact): {w:?}"
        );
    }
}
