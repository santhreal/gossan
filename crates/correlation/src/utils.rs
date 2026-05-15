//! Utility helpers for correlation rule evaluation.

pub(crate) fn normalize_host(target: &str) -> String {
    let mut s = target;
    if let Some(rest) = s.strip_prefix("http://") {
        s = rest;
    } else if let Some(rest) = s.strip_prefix("https://") {
        s = rest;
    }

    // We only want to strip the port/path if it looks like a standard URL format.
    // E.g. we want to keep paths if they are actually part of the unique target identifier in some context,
    // but the gap tests want to ensure `http://domain.com:80` matches `https://domain.com:443`.
    // Let's use a simple approach: if we stripped http/https, OR if it has a port but no slash before the port.

    let is_url_like = target.starts_with("http://") || target.starts_with("https://");

    if is_url_like {
        if let Some(idx) = s.find(':') {
            s = &s[..idx];
        }
        if let Some(idx) = s.find('/') {
            s = &s[..idx];
        }
    } else {
        // We should strip trailing paths even for targets that omit http:// but have them
        if let Some(idx) = s.find('/') {
            s = &s[..idx];
        }

        // If it's a raw domain or IP, we just strip the port if it's there.
        // We shouldn't strip trailing paths blindly for unicode targets that don't have http://
        if let Some(idx) = s.find(':') {
            // Only strip if what follows looks like a port (digits).
            if s[idx + 1..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .count()
                > 0
            {
                s = &s[..idx];
            }
        }
    }

    s.to_string()
}
