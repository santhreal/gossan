use gossan_cloud::{
    azure::AzureProvider, common, do_spaces::DoSpacesProvider, gcs::GcsProvider, permutations,
    provider::CloudProvider, s3::S3Provider,
};

#[test]
fn test_legendary_unit_make_target() {
    let t1 = common::make_target("example.com");
    assert_eq!(t1.domain().unwrap(), "example.com");

    let t2 = common::make_target("https://secure.example.com/");
    // make_target in common.rs does not do URL parsing, it just sets the domain directly.
    assert_eq!(t2.domain().unwrap(), "https://secure.example.com/");
}

#[test]
fn test_legendary_unit_is_xml_listing() {
    assert!(common::is_xml_listing(
        "<?xml version=\"1.0\"?><ListBucketResult><Name>test</Name></ListBucketResult>"
    ));
    assert!(!common::is_xml_listing(
        "<EnumerationResults ServiceEndpoint=\"https://test.blob.core.windows.net/\">"
    ));
    assert!(common::is_xml_listing("<Contents>test</Contents>"));
    assert!(!common::is_xml_listing("<html><body>Hello</body></html>"));
    assert!(!common::is_xml_listing(""));
}

#[test]
fn test_legendary_unit_permutations_generate() {
    let perms = permutations::generate("example");
    assert!(!perms.is_empty(), "Permutations should not be empty");
    assert!(
        perms.contains(&"example".to_string()),
        "Should contain the base name"
    );
    assert!(
        perms.contains(&"example-assets".to_string()),
        "Should contain common suffix"
    );
    assert!(
        perms.iter().all(|p| p.len() >= 3 && p.len() <= 63),
        "All names should be 3-63 chars"
    );
}

#[test]
fn test_legendary_unit_providers() {
    let s3 = S3Provider;
    assert_eq!(s3.name(), "s3");
    assert_eq!(s3.endpoint("test"), "https://test.s3.amazonaws.com/");

    let gcs = GcsProvider;
    assert_eq!(gcs.name(), "gcs");
    // As per gcs.rs implementation
    assert_eq!(gcs.endpoint("test"), "https://test.storage.googleapis.com/");

    let azure = AzureProvider;
    assert_eq!(azure.name(), "azure");
    assert_eq!(
        azure.endpoint("test"),
        "https://test.blob.core.windows.net/"
    );

    let do_spaces = DoSpacesProvider;
    assert_eq!(do_spaces.name(), "spaces");
    assert_eq!(
        do_spaces.endpoint("test"),
        "https://test.ams3.digitaloceanspaces.com/" // The implementation defaults to ams3
    );
}
