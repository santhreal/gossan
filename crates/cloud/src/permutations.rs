/// Generate bucket/account name candidates from an org name.
/// These are the patterns attackers enumerate — we do the same.
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
            Err(e) => {
                tracing::error!(error = %e, "failed to parse built-in permutations.toml");
                // Fallback to minimal hardcoded lists only on parse failure
                PermutationConfig {
                    suffixes: StringList {
                        values: vec![
                            "".to_string(),
                            "-assets".to_string(),
                            "-static".to_string(),
                            "-dev".to_string(),
                            "-prod".to_string(),
                        ],
                    },
                    prefixes: StringList {
                        values: vec![
                            "".to_string(),
                            "assets-".to_string(),
                            "dev-".to_string(),
                        ],
                    },
                    transforms: Transforms {
                        dot_to_hyphen: true,
                        hyphen_to_dot: true,
                    },
                }
            }
        }
    })
}

/// Generate bucket/account name candidates from an organization name.
pub fn generate(org: &str) -> Vec<String> {
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

    // Apply transforms based on configuration
    if config.transforms.dot_to_hyphen {
        candidates.insert(o.replace('.', "-"));
    }
    if config.transforms.hyphen_to_dot {
        candidates.insert(o.replace('-', "."));
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
        assert!(!config.suffixes.values.is_empty(), "should have suffixes from TOML");
        assert!(!config.prefixes.values.is_empty(), "should have prefixes from TOML");
    }

    #[test]
    fn permutations_include_expected_suffixes() {
        let config = builtin_permutations();
        let suffixes = &config.suffixes.values;
        
        // Check for common suffixes
        assert!(suffixes.contains(&"".to_string()), "should include empty suffix");
        assert!(suffixes.contains(&"-assets".to_string()), "should include -assets");
        assert!(suffixes.contains(&"-prod".to_string()), "should include -prod");
        assert!(suffixes.contains(&"-backup".to_string()), "should include -backup");
    }

    #[test]
    fn permutations_include_expected_prefixes() {
        let config = builtin_permutations();
        let prefixes = &config.prefixes.values;
        
        // Check for common prefixes
        assert!(prefixes.contains(&"".to_string()), "should include empty prefix");
        assert!(prefixes.contains(&"assets-".to_string()), "should include assets-");
        assert!(prefixes.contains(&"dev-".to_string()), "should include dev-");
    }

    #[test]
    fn transforms_are_enabled() {
        let config = builtin_permutations();
        assert!(config.transforms.dot_to_hyphen, "dot_to_hyphen should be enabled");
        assert!(config.transforms.hyphen_to_dot, "hyphen_to_dot should be enabled");
    }
}
