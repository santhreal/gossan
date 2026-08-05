//! Output path sanitization.
//!
//! Prevents directory traversal in scanner output by stripping or encoding
//! path separators and parent-directory sequences from server-controlled
//! strings before they are embedded in [`Finding`] fields.
//!
//! **CRLF injection guard**: `\r` and `\n` are both stripped (replaced with
//! `_`) so that a server-controlled excerpt or path can never be placed in an
//! HTTP header value and split it. Any caller that embeds `sanitize()` output
//! in a request header is protected even if the source is adversarial.

/// Sanitize a string so it is safe to use as a filesystem path component
/// **and** safe to embed in HTTP headers (CRLF-clean).
///
/// Replaces `/`, `\`, `\0`, `\r`, `\n`, and `..` with safe alternatives.
pub fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '/' | '\\' | '\0' | '\r' | '\n' => out.push('_'),
            _ => out.push(ch),
        }
    }
    // Collapse multiple dots that could form traversal sequences
    out.replace("..", "__")
}

/// Sanitize a URL path for embedding in finding titles / details.
pub fn sanitize_url_path(path: &str) -> String {
    sanitize(path)
}

/// Sanitize an arbitrary body excerpt to prevent traversal in output.
pub fn sanitize_excerpt(excerpt: &str, max_len: usize) -> String {
    let truncated: String = excerpt.chars().take(max_len).collect();
    sanitize(&truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_replaces_path_separators() {
        assert_eq!(sanitize("foo/bar"), "foo_bar");
        assert_eq!(sanitize("foo\\bar"), "foo_bar");
    }

    #[test]
    fn sanitize_collapses_dotdot() {
        // Each `..` becomes `__`, each `/` becomes `_`. Three traversal
        // chunks separated by single `/` collapse to nine underscores.
        assert_eq!(sanitize("../../../etc/passwd"), "_________etc_passwd");
    }

    #[test]
    fn sanitize_url_path_is_safe() {
        assert_eq!(sanitize_url_path("/api/v1/admin"), "_api_v1_admin");
        // ..\..\windows\system32: `\` and `..` both collapse to `_`,
        // producing six underscores followed by `windows_system32`.
        assert_eq!(
            sanitize_url_path("..\\..\\windows\\system32"),
            "______windows_system32"
        );
    }

    #[test]
    fn sanitize_excerpt_respects_max_len() {
        let long = "a".repeat(1000);
        let sanitized = sanitize_excerpt(&long, 200);
        assert_eq!(sanitized.len(), 200);
    }

    #[test]
    fn sanitize_replaces_null_bytes() {
        assert_eq!(sanitize("foo\0bar"), "foo_bar");
    }

    #[test]
    fn sanitize_preserves_single_dot() {
        assert_eq!(sanitize("foo./bar"), "foo._bar");
        assert_eq!(sanitize(".htaccess"), ".htaccess");
    }

    #[test]
    fn sanitize_excerpt_handles_unicode() {
        let s = "日本語テスト";
        let excerpt = sanitize_excerpt(s, 3);
        assert_eq!(excerpt, "日本語");
    }

    #[test]
    fn sanitize_collapses_multiple_separators() {
        assert_eq!(sanitize("a//b"), "a__b");
        assert_eq!(sanitize("a\\\\b"), "a__b");
    }

    #[test]
    fn sanitize_excerpt_preserves_unicode_length() {
        let s = "🦀Rust🦀";
        let excerpt = sanitize_excerpt(s, 3);
        assert_eq!(excerpt, "🦀Ru");
    }

    #[test]
    fn sanitize_handles_long_input() {
        let input = "a".repeat(10_000);
        let out = sanitize(&input);
        assert_eq!(out.len(), 10_000);
    }

    #[test]
    fn sanitize_empty_string() {
        assert_eq!(sanitize(""), "");
    }

    #[test]
    fn sanitize_single_char() {
        assert_eq!(sanitize("a"), "a");
    }

    #[test]
    fn sanitize_only_separators() {
        assert_eq!(sanitize("///"), "___");
    }

    #[test]
    fn sanitize_only_backslashes() {
        assert_eq!(sanitize("\\\\\\"), "___");
    }

    #[test]
    fn sanitize_only_dots() {
        assert_eq!(sanitize("..."), "__.");
    }

    #[test]
    fn sanitize_mixed_traversal() {
        assert_eq!(sanitize("a/../b/./c"), "a____b_._c");
    }

    #[test]
    fn sanitize_url_path_with_query() {
        assert_eq!(sanitize_url_path("/api?foo=bar"), "_api?foo=bar");
    }

    #[test]
    fn sanitize_url_path_with_fragment() {
        assert_eq!(sanitize_url_path("/api#section"), "_api#section");
    }

    #[test]
    fn sanitize_excerpt_empty() {
        assert_eq!(sanitize_excerpt("", 10), "");
    }

    #[test]
    fn sanitize_excerpt_exact_length() {
        let s = "abcde";
        assert_eq!(sanitize_excerpt(s, 5), "abcde");
    }

    #[test]
    fn sanitize_excerpt_over_length() {
        let s = "abcdefghij";
        assert_eq!(sanitize_excerpt(s, 5), "abcde");
    }

    #[test]
    fn sanitize_excerpt_with_null_bytes() {
        let s = "ab\0cd";
        assert_eq!(sanitize_excerpt(s, 10), "ab_cd");
    }

    #[test]
    fn sanitize_excerpt_with_unicode_and_max_len() {
        let s = "🦀Rust🦀";
        assert_eq!(sanitize_excerpt(s, 3), "🦀Ru");
    }

    #[test]
    fn sanitize_special_chars_preserved() {
        assert_eq!(sanitize("!@#$%^&*()"), "!@#$%^&*()");
    }

    #[test]
    fn sanitize_url_path_with_traversal_and_query() {
        assert_eq!(sanitize_url_path("../../admin?debug=1"), "______admin?debug=1");
    }

    /// §15 AUDIT: CRLF injection guard: `\r` and `\n` in server-controlled
    /// strings must not survive into Finding fields or HTTP headers.
    #[test]
    fn sanitize_strips_crlf_bytes() {
        assert_eq!(sanitize("foo\r\nbar"), "foo__bar", "CR+LF both stripped");
        assert_eq!(sanitize("X-Header: val\r\nInjected: hdr"), "X-Header: val__Injected: hdr");
        assert_eq!(sanitize("\nroot"), "_root");
        assert_eq!(sanitize("end\r"), "end_");
    }

    /// CRLF must also be stripped inside excerpts.
    #[test]
    fn sanitize_excerpt_strips_crlf() {
        let s = "good\r\nbad";
        let out = sanitize_excerpt(s, 50);
        assert!(!out.contains('\r'), "CR must not survive sanitize_excerpt");
        assert!(!out.contains('\n'), "LF must not survive sanitize_excerpt");
    }

    /// Adversarial: empty and single-char inputs must not panic.
    #[test]
    fn sanitize_empty_and_single_char() {
        assert_eq!(sanitize(""), "");
        assert_eq!(sanitize("."), ".");
        assert_eq!(sanitize("/"), "_");
        assert_eq!(sanitize("\\"), "_");
        assert_eq!(sanitize("\0"), "_");
    }

    /// Adversarial: extreme-length input must not panic and must stay bounded.
    #[test]
    fn sanitize_extreme_length() {
        let input = "a".repeat(1_000_000);
        let out = sanitize(&input);
        assert_eq!(out.len(), 1_000_000);
    }

    /// Adversarial: path traversal with mixed separators and null bytes.
    #[test]
    fn sanitize_mixed_traversal_and_nulls() {
        let input = "..\0/../etc/passwd\0";
        let out = sanitize(input);
        assert!(!out.contains('/'));
        assert!(!out.contains('\\'));
        assert!(!out.contains('\0'));
        assert!(out.contains("__"));
    }

    /// Property tests for path sanitization.
    #[cfg(test)]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn prop_sanitize_never_contains_path_separators(s in "\\PC*") {
                let out = sanitize(&s);
                prop_assert!(!out.contains('/'));
                prop_assert!(!out.contains('\\'));
                prop_assert!(!out.contains('\0'));
                prop_assert!(!out.contains('\r'), "CR must be stripped (CRLF injection guard)");
                prop_assert!(!out.contains('\n'), "LF must be stripped (CRLF injection guard)");
            }

            #[test]
            fn prop_sanitize_excerpt_respects_max_len(
                s in "\\PC*",
                max_len in 0usize..1024
            ) {
                let out = sanitize_excerpt(&s, max_len);
                // Unicode-aware length check: count chars, not bytes
                prop_assert!(out.chars().count() <= max_len);
            }

            #[test]
            fn prop_sanitize_idempotent(s in "\\PC*") {
                let once = sanitize(&s);
                let twice = sanitize(&once);
                prop_assert_eq!(once, twice);
            }
        }
    }
}
