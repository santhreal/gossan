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
///
/// Only the `<ListBucketResult` root element is checked; a bare `<Contents>`
/// substring appears in unrelated XML APIs and HTML pages, so matching it
/// would produce false-positive Critical findings.
pub fn is_xml_listing(body: &str) -> bool {
    body.contains("<ListBucketResult")
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
        // A bare <Contents> tag is NOT sufficient, unrelated XML APIs and
        // HTML pages can contain it, causing false-positive Critical findings.
        assert!(!is_xml_listing("<Contents>file</Contents>"));
        assert!(!is_xml_listing("<html>not a bucket</html>"));
    }
}
