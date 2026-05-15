use gossan_cloud::{permutations, provider::CloudProvider, s3::S3Provider};

#[test]
fn test_legendary_gap_permutations_generates_invalid_lengths() {
    // ORIGINAL GAP (now fixed): `permutations::generate` used to apply transforms
    // `dot_to_hyphen` / `hyphen_to_dot` AFTER the length checks (3..=63), so an
    // input like "a." produced "a-" — length 2 — bypassing the bucket-name
    // length rule. The fix moved the length check to AFTER transforms.
    //
    // This test now asserts the post-fix invariant (no output with length
    // outside 3..=63) on inputs that would previously have leaked.

    let inputs = [
        "a.",  // would have produced "a-" (len 2)
        "a-",  // would have produced "a." (len 2)
        "a.b", // produces "a-b" (len 3, valid)
        // Long input that, after transforms, must still respect the 63 cap.
        &"a".repeat(60),
        &"a.".repeat(40),
    ];

    for input in inputs {
        let perms = permutations::generate(input);
        for p in &perms {
            assert!(
                (3..=63).contains(&p.len()),
                "permutations::generate({:?}) produced {:?} with length {} (must be 3..=63)",
                input,
                p,
                p.len(),
            );
        }
    }

    // The previously-leaking shape MUST NOT appear.
    let perms_a_dot = permutations::generate("a.");
    assert!(
        !perms_a_dot.contains(&"a-".to_string()),
        "regression: 2-char permutation 'a-' leaked back through generate(\"a.\")"
    );
}

#[tokio::test]
async fn test_legendary_gap_s3_provider_does_not_url_encode() {
    // GAP FINDING: `S3Provider::endpoint` simply interpolates the name into the URL without URL encoding it.
    // If a candidate name has a space or special characters, it could result in an invalid URL and a runtime crash
    // or unhandled error during the request.
    let provider = S3Provider;
    let url = provider.endpoint("my bucket");

    // According to S3 bucket naming rules, spaces are not allowed.
    // But since the provider's job is just to format the URL, we expect it to correctly URL-encode inputs,
    // or handle them gracefully. Here we test the gap that it does NOT encode.
    // Since we write a test that EXPECTS the correct behaviour, we assert that it does encode.
    // This will fail because the implementation is naive.
    assert_eq!(
        url, "https://my%20bucket.s3.amazonaws.com/",
        "BUG: S3Provider does not URL-encode bucket names!"
    );
}
