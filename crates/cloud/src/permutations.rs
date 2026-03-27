/// Generate bucket/account name candidates from an org name.
/// These are the patterns attackers enumerate — we do the same.
pub fn generate(org: &str) -> Vec<String> {
    let o = org.to_lowercase();

    // Common suffixes and prefixes seen in misconfigured buckets
    let suffixes = [
        "",
        "-assets",
        "-static",
        "-media",
        "-images",
        "-img",
        "-uploads",
        "-files",
        "-docs",
        "-documents",
        "-data",
        "-backup",
        "-backups",
        "-bak",
        "-archive",
        "-archives",
        "-logs",
        "-log",
        "-dev",
        "-development",
        "-staging",
        "-stage",
        "-prod",
        "-production",
        "-test",
        "-testing",
        "-qa",
        "-uat",
        "-public",
        "-private",
        "-internal",
        "-infra",
        "-infrastructure",
        "-storage",
        "-store",
        "-cdn",
        "-cache",
        "-tmp",
        "-temp",
        "-web",
        "-site",
        "-api",
        "-app",
        "-s3",
        "-bucket",
        "-admin",
        "-dashboard",
        "-config",
        "-secrets",
        "-creds",
        "-jenkins",
        "-ci",
        "-build",
        "-releases",
        "-deploy",
        "-email",
        "-mail",
        "-db",
        "-database",
    ];

    let prefixes = [
        "", "assets-", "static-", "media-", "backup-", "dev-", "staging-", "prod-", "test-",
        "cdn-", "s3-", "storage-",
    ];

    let mut candidates = std::collections::HashSet::new();

    for suffix in &suffixes {
        for prefix in &prefixes {
            let name = format!("{}{}{}", prefix, o, suffix);
            // S3/GCS bucket names: 3–63 chars, lowercase alphanumeric + hyphens
            if name.len() >= 3 && name.len() <= 63 {
                candidates.insert(name);
            }
        }
    }

    // Also try with dots replaced by hyphens and vice versa
    candidates.insert(o.replace('.', "-"));
    candidates.insert(o.replace('-', "."));

    candidates.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

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
        let unique = candidates.iter().collect::<HashSet<_>>();
        assert_eq!(unique.len(), candidates.len());
    }

    #[test]
    fn generate_normalizes_case_and_preserves_valid_lengths() {
        let candidates = generate("ExAmPlE");
        assert!(candidates.iter().all(|name| name == &name.to_lowercase()));
        assert!(candidates.iter().all(|name| (3..=63).contains(&name.len())));
    }
}
