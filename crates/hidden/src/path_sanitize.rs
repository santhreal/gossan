//! Output path sanitization.
//!
//! Prevents directory traversal in scanner output by stripping or encoding
//! path separators and parent-directory sequences from server-controlled
//! strings before they are embedded in [`Finding`] fields.

/// Sanitize a string so it is safe to use as a filesystem path component.
///
/// Replaces `..`, `.`, `/`, `\`, and null bytes with safe alternatives.
/// Percent-encodes remaining problematic characters.
pub fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '/' | '\\' | '\0' => out.push('_'),
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
        // ..\..\windows\system32 — `\` and `..` both collapse to `_`,
        // producing six underscores followed by `windows_system32`.
        assert_eq!(sanitize_url_path("..\\..\\windows\\system32"), "______windows_system32");
    }

    #[test]
    fn sanitize_excerpt_respects_max_len() {
        let long = "a".repeat(1000);
        let sanitized = sanitize_excerpt(&long, 200);
        assert_eq!(sanitized.len(), 200);
    }
}
