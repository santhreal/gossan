//! Extraction logic for turning HTTP responses into findings.

use crate::git_env::rules::OwnedCheck;
use gossan_core::Target;
use secfinding::{Evidence, Finding, Severity};

/// Magic bytes for file format detection.
mod magic {
    pub const ZIP: &[&[u8]] = &[b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"];
    pub const GZIP: &[u8] = &[0x1f, 0x8b];
    pub const TAR: &[u8] = b"ustar";
    pub const VIM_SWAP: &[u8] = b"b0VIM";
    pub const DS_STORE: &[&[u8]] = &[b"BUD1", b"bplist"];
}

fn has_magic_bytes(data: &[u8], magics: &[&[u8]]) -> bool {
    magics
        .iter()
        .any(|magic| data.len() >= magic.len() && data.starts_with(magic))
}

fn is_zip_file(data: &[u8]) -> bool {
    has_magic_bytes(data, magic::ZIP)
}

fn is_gzip_file(data: &[u8]) -> bool {
    data.len() >= 2 && data.starts_with(magic::GZIP)
}

fn is_tar_file(data: &[u8]) -> bool {
    data.len() >= 262 && data[257..].starts_with(magic::TAR)
}

fn is_vim_swap(data: &[u8]) -> bool {
    data.starts_with(magic::VIM_SWAP)
}

fn is_ds_store(data: &[u8]) -> bool {
    has_magic_bytes(data, magic::DS_STORE)
}

fn magic_confirms(path: &str, data: &[u8]) -> bool {
    if path.contains("heapdump") {
        return data.starts_with(b"JAVA PROFILE");
    }
    if path.ends_with(".zip") {
        return is_zip_file(data);
    }
    if path.ends_with(".tar.gz") {
        return is_gzip_file(data) || is_tar_file(data);
    }
    if path.ends_with(".swp") {
        return is_vim_swap(data);
    }
    if path.ends_with(".DS_Store") {
        return is_ds_store(data);
    }
    true
}

/// Processes a single check and returns any findings.
pub async fn process_check(
    client: reqwest::Client,
    base: String,
    target: Target,
    check: OwnedCheck,
    is_catch_all: bool,
    rate_limiter: std::sync::Arc<crate::HostRateLimiter>,
    host: String,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let url = format!("{}{}", base, check.path);

    if is_catch_all && check.content_probe.is_none() {
        return findings;
    }

    rate_limiter.wait_for_host(&host).await;
    let Ok(resp) = client.get(&url).send().await else {
        return findings;
    };
    let status = resp.status().as_u16();
    rate_limiter.observe_status(&host, status).await;

    if status == 200 {
        let bytes = match crate::soft404::read_limited(resp, crate::MAX_BODY_BYTES).await {
            Some(b) => b,
            None => return findings,
        };

        if is_catch_all {
            let looks_like_html = String::from_utf8_lossy(&bytes)
                .trim_start()
                .starts_with('<');
            if looks_like_html {
                return findings;
            }
        }

        // Magic byte validation for binary paths
        if !magic_confirms(&check.path, &bytes) {
            return findings;
        }

        let body = String::from_utf8_lossy(&bytes).into_owned();

        if let Some(ref probe_str) = check.content_probe {
            if !body.contains(probe_str.as_str()) {
                return findings;
            }
        }

        let safe_path = crate::path_sanitize::sanitize_url_path(&check.path);

        gossan_core::try_push_finding(
            crate::finding_builder(
                &target,
                check.severity,
                check.title.as_str(),
                check.detail.as_str(),
            )
            .evidence(Evidence::HttpResponse {
                status,
                headers: vec![],
                body_excerpt: Some(body.chars().take(300).collect::<String>().into()),
            })
            .tag("exposure")
            .tag(check.tag.as_str()),
            &mut findings,
        );
    } else if status == 403
        && matches!(
            check.tag.as_str(),
            "git" | "actuator" | "admin" | "keys" | "cloud"
        )
    {
        gossan_core::try_push_finding(
            crate::finding_builder(
                &target,
                Severity::Low,
                format!("{} (403 — exists, access denied)", check.title),
                format!("{} (HTTP 403)", check.detail),
            )
            .evidence(Evidence::HttpResponse {
                status,
                headers: vec![],
                body_excerpt: None,
            })
            .tag("exposure")
            .tag(check.tag.as_str()),
            &mut findings,
        );
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zip_magic_detection() {
        assert!(is_zip_file(b"PK\x03\x04some zip content"));
        assert!(!is_zip_file(b"not a zip file"));
    }

    #[test]
    fn gzip_magic_detection() {
        let gzip_data = [0x1f, 0x8b, 0x08, 0x00];
        assert!(is_gzip_file(&gzip_data));
        assert!(!is_gzip_file(b"not gzip"));
    }

    #[test]
    fn vim_swap_magic_detection() {
        assert!(is_vim_swap(b"b0VIM 9.0 some swap data"));
        assert!(!is_vim_swap(b"not a vim swap"));
    }

    #[test]
    fn ds_store_magic_detection() {
        assert!(is_ds_store(b"BUD1"));
        assert!(!is_ds_store(b"not ds_store"));
    }

    #[test]
    fn magic_confirms_respects_path_extension() {
        assert!(magic_confirms("/backup.zip", b"PK\x03\x04"));
        assert!(!magic_confirms("/backup.zip", b"not zip"));
        assert!(magic_confirms("/backup.tar.gz", b"\x1f\x8b"));
        assert!(magic_confirms("/index.php", b"<?php"));
    }
}
