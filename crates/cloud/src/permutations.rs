//! Bucket/asset name permutation generation from organization names.

/// Generate bucket/account name candidates from an org name.
/// These are the patterns attackers enumerate (we do the same).
use serde::Deserialize;
use std::sync::OnceLock;

/// Permutation configuration from TOML.
#[derive(Debug, Clone, Deserialize)]
struct PermutationConfig {
    suffixes: StringList,
    prefixes: StringList,
    transforms: Transforms,
}

#[derive(Debug, Clone, Deserialize)]
struct StringList {
    values: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Transforms {
    #[serde(rename = "dot_to_hyphen")]
    dot_to_hyphen: bool,
    #[serde(rename = "hyphen_to_dot")]
    hyphen_to_dot: bool,
}

/// Built-in permutations.toml content (embedded at compile time).
const BUILTIN_PERMUTATIONS: &str = include_str!("../rules/permutations.toml");

/// Global cache for built-in permutations.
static PERMUTATIONS: OnceLock<PermutationConfig> = OnceLock::new();

/// Initialize and return the built-in permutation config.
fn builtin_permutations() -> &'static PermutationConfig {
    PERMUTATIONS.get_or_init(|| {
        match toml::from_str::<PermutationConfig>(BUILTIN_PERMUTATIONS) {
            Ok(config) => config,
            Err(e) => panic!("gossan-cloud: built-in permutations.toml is malformed: {e}"),
        }
    })
}

/// Maximum length of a cloud bucket/account name (S3/GCS/Spaces/Azure).
const MAX_BUCKET_LEN: usize = 63;

/// Generate bucket/account name candidates from an organization name.
pub fn generate(org: &str) -> Vec<String> {
    // Reject absurdly long org names up-front to prevent DoS via
    // unbounded allocation in to_lowercase() / format!() / replace().
    if org.len() > MAX_BUCKET_LEN {
        return Vec::new();
    }
    let o = org.to_lowercase();
    let config = builtin_permutations();
    let suffixes = &config.suffixes.values;
    let prefixes = &config.prefixes.values;

    let mut candidates = std::collections::HashSet::new();

    for suffix in suffixes {
        for prefix in prefixes {
            let name = format!("{}{}{}", prefix, o, suffix);
            // S3/GCS bucket names: 3–63 chars, lowercase alphanumeric + hyphens
            if name.len() >= 3 && name.len() <= 63 {
                candidates.insert(name);
            }
        }
    }

    // Apply transforms based on configuration, but validate length AFTER transformation
    if config.transforms.dot_to_hyphen {
        let transformed = o.replace('.', "-");
        if transformed.len() >= 3 && transformed.len() <= 63 {
            candidates.insert(transformed);
        }
    }
    if config.transforms.hyphen_to_dot {
        let transformed = o.replace('-', ".");
        if transformed.len() >= 3 && transformed.len() <= 63 {
            candidates.insert(transformed);
        }
    }

    candidates.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_includes_expected_prefix_and_suffix_forms() {
        let candidates = generate("example");
        assert!(candidates.contains(&"example-assets".to_string()));
        assert!(candidates.contains(&"assets-example".to_string()));
        assert!(candidates.contains(&"example".to_string()));
    }

    #[test]
    fn generate_deduplicates_candidates() {
        let candidates = generate("example");
        let unique = candidates.iter().collect::<std::collections::HashSet<_>>();
        assert_eq!(unique.len(), candidates.len());
    }

    #[test]
    fn generate_normalizes_case_and_preserves_valid_lengths() {
        let candidates = generate("ExAmPlE");
        assert!(candidates.iter().all(|name| name == &name.to_lowercase()));
        assert!(candidates.iter().all(|name| (3..=63).contains(&name.len())));
    }

    #[test]
    fn permutations_load_from_toml() {
        let config = builtin_permutations();
        assert!(
            !config.suffixes.values.is_empty(),
            "should have suffixes from TOML"
        );
        assert!(
            !config.prefixes.values.is_empty(),
            "should have prefixes from TOML"
        );
    }

    #[test]
    fn permutations_include_expected_suffixes() {
        let config = builtin_permutations();
        let suffixes = &config.suffixes.values;

        // Check for common suffixes
        assert!(
            suffixes.contains(&"".to_string()),
            "should include empty suffix"
        );
        assert!(
            suffixes.contains(&"-assets".to_string()),
            "should include -assets"
        );
        assert!(
            suffixes.contains(&"-prod".to_string()),
            "should include -prod"
        );
        assert!(
            suffixes.contains(&"-backup".to_string()),
            "should include -backup"
        );
    }

    #[test]
    fn permutations_include_expected_prefixes() {
        let config = builtin_permutations();
        let prefixes = &config.prefixes.values;

        // Check for common prefixes
        assert!(
            prefixes.contains(&"".to_string()),
            "should include empty prefix"
        );
        assert!(
            prefixes.contains(&"assets-".to_string()),
            "should include assets-"
        );
        assert!(
            prefixes.contains(&"dev-".to_string()),
            "should include dev-"
        );
    }

    #[test]
    fn transforms_are_enabled() {
        let config = builtin_permutations();
        assert!(
            config.transforms.dot_to_hyphen,
            "dot_to_hyphen should be enabled"
        );
        assert!(
            config.transforms.hyphen_to_dot,
            "hyphen_to_dot should be enabled"
        );
    }

    // ── Boundary: OOM guard ──────────────────────────────────────────────

    #[test]
    fn generate_passes_guard_at_exactly_max_but_rejects_one_past() {
        // The OOM guard is `org.len() > MAX_BUCKET_LEN`, so an org of
        // EXACTLY MAX_BUCKET_LEN bytes passes: the bare name (63 chars,
        // produced by the identity transforms) is a valid 3–63 candidate,
        // while every prefix/suffix-decorated form exceeds 63 and is
        // filtered. One byte past the max trips the guard → empty. Pins
        // the `>` (not `>=`) boundary so a future edit can't silently
        // shift it.
        let at_max = generate(&"a".repeat(MAX_BUCKET_LEN));
        assert!(
            !at_max.is_empty(),
            "org of exactly {MAX_BUCKET_LEN} bytes passes the guard (the bare name fits)"
        );
        assert!(
            at_max.iter().all(|c| c.len() == MAX_BUCKET_LEN),
            "at the max only the bare {MAX_BUCKET_LEN}-char form survives; decorated forms exceed 63: {at_max:?}"
        );

        let one_past = generate(&"a".repeat(MAX_BUCKET_LEN + 1));
        assert!(
            one_past.is_empty(),
            "org of {} bytes (one past max) trips the OOM guard → empty",
            MAX_BUCKET_LEN + 1
        );
    }

    #[test]
    fn generate_returns_empty_for_very_long_org() {
        let org = "a".repeat(10_000);
        let candidates = generate(&org);
        assert!(
            candidates.is_empty(),
            "very long org must return empty (OOM guard)"
        );
    }

    #[test]
    fn generate_returns_some_for_org_one_below_max_bucket_len() {
        // An org of MAX_BUCKET_LEN - 1 bytes passes the guard.
        // With an empty prefix+suffix the bare name = 62 bytes which is valid (3–63).
        let org = "a".repeat(MAX_BUCKET_LEN - 1);
        let candidates = generate(&org);
        assert!(
            !candidates.is_empty(),
            "org one byte under limit must produce candidates"
        );
        // All produced candidates must be within length bounds.
        for c in &candidates {
            assert!(
                (3..=63).contains(&c.len()),
                "candidate '{c}' outside [3,63] bounds"
            );
        }
    }

    // ── Boundary: short org names ────────────────────────────────────────

    #[test]
    fn generate_empty_org_returns_empty_or_minimal() {
        let candidates = generate("");
        // All entries must satisfy the 3–63 length gate.
        for c in &candidates {
            assert!(
                (3..=63).contains(&c.len()),
                "candidate '{c}' outside [3,63] bounds for empty org"
            );
        }
    }

    #[test]
    fn generate_single_char_org() {
        let candidates = generate("x");
        // "x" itself is only 1 char; suffix/prefix combos may push it to ≥3.
        for c in &candidates {
            assert!((3..=63).contains(&c.len()));
        }
    }

    #[test]
    fn generate_two_char_org() {
        let candidates = generate("ab");
        for c in &candidates {
            assert!(
                (3..=63).contains(&c.len()),
                "candidate '{c}' violates length gate"
            );
        }
    }

    // ── Anti-rig: lowercase invariant ────────────────────────────────────

    #[test]
    fn generate_all_candidates_are_lowercase() {
        for org in ["Example", "CORP", "MyOrg-2024"] {
            let candidates = generate(org);
            for c in &candidates {
                assert_eq!(*c, c.to_lowercase(), "candidate '{c}' is not lowercase for org='{org}'");
            }
        }
    }

    // ── Anti-rig: no candidate exceeds 63 chars ──────────────────────────

    #[test]
    fn generate_no_candidate_exceeds_max_length() {
        for org in ["example", "my-company", "acme-corp"] {
            let candidates = generate(org);
            for c in &candidates {
                assert!(
                    c.len() <= 63,
                    "candidate '{c}' exceeds 63-char S3 limit for org='{org}'"
                );
            }
        }
    }

    // ── Anti-rig: dedup stability ────────────────────────────────────────

    #[test]
    fn generate_is_idempotent() {
        // Calling generate twice with the same org must return the same SET.
        let mut a = generate("stable-corp");
        let mut b = generate("stable-corp");
        a.sort();
        b.sort();
        assert_eq!(a, b, "generate must be idempotent for the same input");
    }

    // ── Dot/hyphen transform boundary ────────────────────────────────────

    #[test]
    fn generate_dot_to_hyphen_transform_applied() {
        let candidates = generate("my.org");
        assert!(
            candidates.contains(&"my-org".to_string()),
            "dot_to_hyphen transform must produce 'my-org' from 'my.org'"
        );
    }

    #[test]
    fn generate_hyphen_to_dot_transform_applied() {
        let candidates = generate("my-org");
        assert!(
            candidates.contains(&"my.org".to_string()),
            "hyphen_to_dot transform must produce 'my.org' from 'my-org'"
        );
    }
}
