//! Deep precision/truth tests for `gossan_cloud::common::is_xml_listing`.
//!
//! This single pure predicate gates the **Critical** "public cloud
//! bucket exposed" finding for s3 / do_spaces / gcs. A false positive
//! is an embarrassing wrong Critical (a defender chasing a
//! non-existent exposure); a false negative is a missed real exposure.
//! The original `body.contains("<ListBucketResult") ||
//! body.contains("<Contents>")` matched the generic `<Contents>`
//! substring anywhere  -  every real S3/GCS/Spaces listing already
//! carries the `<ListBucketResult` root at the head of the body
//! (size-bounding truncates the TAIL, never the root), so the
//! `<Contents>` arm added zero recall and a wide FP surface.
//!
//! Contract-first: asserts the correct contract; `common.rs` is fixed
//! to satisfy it (and the in-module test that codified the bug is
//! corrected, with justification  -  a bare `<Contents>` fragment is not
//! an S3 listing).

use gossan_cloud::common::is_xml_listing;

/// PROVING: genuine public-listing bodies across the S3-compatible
/// providers (S3, GCS XML API, DigitalOcean Spaces)  -  all rooted at
/// `<ListBucketResult` with provider-specific xmlns.
#[test]
fn real_bucket_listings_are_detected() {
    let s3 = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><Contents><Key>secret.txt</Key></Contents></ListBucketResult>"#;
    let gcs = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://doc.s3.amazonaws.com/2006-03-01"><Name>g</Name><Contents><Key>a</Key></Contents></ListBucketResult>"#;
    let spaces = r#"<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>sp</Name></ListBucketResult>"#;
    for (name, body) in [("s3", s3), ("gcs", gcs), ("spaces", spaces)] {
        assert!(
            is_xml_listing(body),
            "{name}: a real ListBucketResult body must be detected as a listing"
        );
    }
    // An empty-but-PUBLIC bucket: ListBucketResult present, no
    // <Contents>  -  still listable, still an exposure, must be true.
    assert!(
        is_xml_listing(
            r#"<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>empty</Name><KeyCount>0</KeyCount></ListBucketResult>"#
        ),
        "an empty but publicly-listable bucket is still an exposure"
    );
    // Truncated by the body size cap  -  the root is at the head, so it
    // must still be recognised (recall under bounded reads).
    assert!(
        is_xml_listing(
            r#"<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Contents><Key>f"#
        ),
        "a truncated listing whose root survived must still be detected"
    );
}

/// PRECISION (the bug): bodies that contain the generic `<Contents>`
/// tag but are NOT an S3-style bucket listing MUST be false  -  emitting
/// a Critical "public bucket" here is the worst output of a recon tool.
#[test]
fn non_listing_bodies_with_contents_substring_are_not_listings() {
    let cases = [
        // A correctly-SECURED bucket returns an access-denied error XML.
        ("access-denied", r#"<?xml version="1.0"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>"#),
        ("no-such-bucket", r#"<?xml version="1.0"?><Error><Code>NoSuchBucket</Code></Error>"#),
        // An unrelated XML API that simply has a <Contents> element.
        ("unrelated-xml-api", r#"<?xml version="1.0"?><Response><Status>ok</Status><Contents>some app data</Contents></Response>"#),
        // An HTML page that documents/mentions S3 (code sample, blog).
        ("html-doc", r#"<html><body><pre>&lt;Contents&gt;&lt;Key&gt;...&lt;/Key&gt;&lt;/Contents&gt;</pre><Contents>nav</Contents></body></html>"#),
        // A CMS/feed page coincidentally using the tag name.
        ("feed", r#"<feed><entry><Contents>post body</Contents></entry></feed>"#),
        // JSON, not XML at all.
        ("json", r#"{"Contents": [{"Key": "a"}], "Name": "b"}"#),
        ("empty", ""),
        ("plain-404", "404 Not Found"),
    ];
    for (name, body) in cases {
        assert!(
            !is_xml_listing(body),
            "{name}: a non-ListBucketResult body must NOT be classified a \
             public bucket listing (false Critical), body={body:?}"
        );
    }
}

/// ADVERSARIAL: an attacker-influenced response that stuffs the
/// `<Contents>` marker into an error/landing page must not flip the
/// Critical finding; only the genuine listing root does.
#[test]
fn marker_injection_into_non_listing_does_not_trigger() {
    let injected = r#"<?xml version="1.0"?><Error><Code>AccessDenied</Code><Message><Contents><Key>haha</Key></Contents></Message></Error>"#;
    assert!(
        !is_xml_listing(injected),
        "a <Contents> smuggled inside an AccessDenied error is still a \
         denied (secure) bucket, not an exposure"
    );
    // The genuine signal still works even with hostile noise prepended.
    let real_with_noise = r#"garbage <Contents> not really <?xml?> <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Contents><Key>k</Key></Contents></ListBucketResult>"#;
    assert!(
        is_xml_listing(real_with_noise),
        "a genuine ListBucketResult must still be detected amid noise"
    );
}
