//! CDN detection for port-scan skipping.
//!
//! Loading CDN IP ranges from a file avoids hardcoding them in source code.
//! If no file is configured, a lightweight PTR heuristic is used instead.

use std::net::IpAddr;
use std::path::Path;

/// Load CIDR ranges from a file (one per line, `#` comments allowed).
pub fn load_ranges(path: &Path) -> anyhow::Result<Vec<ipnet::IpNet>> {
    let content = std::fs::read_to_string(path)?;
    let mut ranges = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match line.parse::<ipnet::IpNet>() {
            Ok(net) => ranges.push(net),
            Err(e) => tracing::warn!(line = line, err = %e, "skipping malformed CIDR"),
        }
    }
    tracing::info!(count = ranges.len(), path = %path.display(), "loaded CDN ranges");
    Ok(ranges)
}

/// Check whether an IP falls inside any of the provided ranges.
pub fn is_cdn_ip(ip: IpAddr, ranges: &[ipnet::IpNet]) -> bool {
    ranges.iter().any(|net| net.contains(&ip))
}

/// Lightweight heuristic: query PTR for the IP and look for known
/// CDN hostnames. Used when no explicit range file is configured.
///
/// `resolver` is the standard `hickory_resolver::TokioAsyncResolver`
/// — gossan-portscan already depends on hickory transitively via
/// gossan-core, so we take the resolver directly rather than
/// re-exporting it.
pub async fn ptr_heuristic(
    resolver: &hickory_resolver::TokioAsyncResolver,
    ip: IpAddr,
) -> bool {
    let Ok(name) = resolver.reverse_lookup(ip).await else {
        return false;
    };
    for n in name.iter() {
        let s = n.to_utf8().to_lowercase();
        if s.contains("cloudflare")
            || s.contains("fastly")
            || s.contains("akamai")
            || s.contains("edgecast")
            || s.contains("incapdns")
            || s.contains("amazonaws")
            || s.contains("googleusercontent")
            || s.contains("azure")
        {
            tracing::debug!(ip = %ip, ptr = %s, "CDN detected via PTR heuristic");
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn load_ranges_parses_valid_cidrs() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "# comment").unwrap();
        writeln!(tmp, "1.1.1.0/24").unwrap();
        writeln!(tmp).unwrap();
        writeln!(tmp, "10.0.0.0/8").unwrap();
        writeln!(tmp, "garbage-not-a-cidr").unwrap();
        let ranges = load_ranges(tmp.path()).unwrap();
        assert_eq!(ranges.len(), 2);
    }

    #[test]
    fn load_ranges_returns_err_on_missing_file() {
        let r = load_ranges(std::path::Path::new("/nonexistent/file"));
        assert!(r.is_err());
    }

    #[test]
    fn is_cdn_ip_matches_loaded_range() {
        let ranges: Vec<ipnet::IpNet> = vec!["1.1.1.0/24".parse().unwrap()];
        assert!(is_cdn_ip("1.1.1.5".parse().unwrap(), &ranges));
        assert!(!is_cdn_ip("8.8.8.8".parse().unwrap(), &ranges));
    }

    #[test]
    fn is_cdn_ip_empty_ranges_never_matches() {
        let ranges: Vec<ipnet::IpNet> = Vec::new();
        assert!(!is_cdn_ip("1.1.1.1".parse().unwrap(), &ranges));
    }
}
