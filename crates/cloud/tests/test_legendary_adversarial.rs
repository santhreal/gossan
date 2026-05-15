use gossan_cloud::{common, permutations};

#[test]
fn test_legendary_adversarial_permutations_generate() {
    let large_str1 = "A".repeat(100);
    let large_str2 = "A".repeat(1_000_000);
    let large_str3 = "a".repeat(63);
    let large_str4 = "a".repeat(64);

    let inputs = [
        "", // Empty input
        "\0", // Null byte
        "\x00\x00\x00\x00\x00",
        "a", // Too small? Wait, `generate` filters len >= 3 and <= 63. But what if org is "a"? It generates `a-assets` which is fine.
        &large_str1, // Huge input (exceeds 63 chars max limit normally). `generate` will just drop items.
        &large_str2, // 1MB+ input
        "👨‍👩‍👧‍👦", // Unicode / Zalgo
        "../../../../../etc/passwd", // Path traversal
        &large_str3, // Boundary 63
        &large_str4, // Boundary 64
        "\u{FFFF}", // Boundary unicode
    ];

    for input in inputs.iter() {
        let _ = permutations::generate(input); // Just ensure it doesn't panic. We check that it handles strings safely.
    }
}

#[test]
fn test_legendary_adversarial_is_xml_listing() {
    let massive = "A".repeat(1_000_000);
    let pre_content = format!("{}{}", "A".repeat(100_000), "<Contents>");
    let post_content = format!("<Contents>{}", "B".repeat(100_000));

    let inputs = [
        "",
        "\0",
        &massive, // Massive string
        "<ListBucketResult>",
        &pre_content,
        &post_content,
        "../../../../../etc/passwd",
        "👨‍👩‍👧‍👦", // Unicode / Zalgo
        "\u{FFFF}", // Boundary unicode
    ];

    for input in inputs.iter() {
        let _ = common::is_xml_listing(input); // Just ensure it doesn't panic.
    }
}

#[test]
fn test_legendary_adversarial_make_target() {
    let massive = "A".repeat(1_000_000);
    let inputs = [
        "", // Empty input
        "\0", // Null byte
        &massive, // Massive string
        "../../../../../etc/passwd", // Path traversal
        "👨‍👩‍👧‍👦", // Unicode / Zalgo
        "\u{FFFF}", // Boundary unicode
    ];

    for input in inputs.iter() {
        let t = common::make_target(input);
        assert_eq!(t.domain().unwrap(), *input); // It simply assigns it directly.
    }
}
