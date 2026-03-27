//! Shared helpers used by all cloud provider probes.

use gossan_core::{DiscoverySource, DomainTarget, Target};

/// Build the scan-seed `Target`. Used once per scan seed; passed into every provider.
pub fn make_target(seed: &str) -> Target {
    Target::Domain(DomainTarget {
        domain: seed.to_string(),
        source: DiscoverySource::Seed,
    })
}

/// Returns `true` if `body` looks like an S3/GCS/Spaces XML directory listing.
pub fn is_xml_listing(body: &str) -> bool {
    body.contains("<ListBucketResult") || body.contains("<Contents>")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_target_preserves_seed_domain() {
        let target = make_target("example.com");
        assert_eq!(target.domain(), Some("example.com"));
    }

    #[test]
    fn xml_listing_detection_matches_bucket_markers() {
        assert!(is_xml_listing(
            "<ListBucketResult><Contents>file</Contents></ListBucketResult>"
        ));
        assert!(is_xml_listing("<Contents>file</Contents>"));
        assert!(!is_xml_listing("<html>not a bucket</html>"));
    }
}
