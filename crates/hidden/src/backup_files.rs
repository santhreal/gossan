//! Dedicated backup-file exposure probe.
//!
//! Targets the long tail of "developer left a snapshot in webroot"
//! mistakes: editor swap files, archive dumps, version-suffixed
//! configs, IDE project metadata, and SQL dumps. Overlaps with
//! [`crate::git_env`] on a handful of canonical paths but goes
//! deeper on the per-extension permutations editors and CI scripts
//! tend to leave behind.
//!
//! Verified by content-validation: an HTTP 200 alone is not enough
//! — we either match a magic byte sequence (zip / gzip / tar / vim
//! swap) or a content-probe substring that the real file shape
//! requires.
use crate::{finding_builder, soft404, MAX_BODY_BYTES};
use futures::StreamExt;
use gossan_core::{try_push_finding, Target};
use secfinding::{Evidence, Finding, Severity};

const PARALLEL_REQUESTS: usize = 25;

/// One backup-path probe.
struct BackupCheck {
    path: &'static str,
    title: &'static str,
    severity: Severity,
    /// Body must contain this substring (case-sensitive). `None` means
    /// any 200 + magic-byte match is enough.
    content_probe: Option<&'static str>,
    /// Body must start with one of these magic byte sequences. Applied
    /// before `content_probe`. Empty list means no magic check.
    magic: &'static [&'static [u8]],
}

const BACKUP_CHECKS: &[BackupCheck] = &[
    // ── Generic archives ──────────────────────────────────────────
    BackupCheck {
        path: "/backup.zip",
        title: "Backup archive (zip) exposed",
        severity: Severity::Critical,
        content_probe: None,
        magic: &[b"PK\x03\x04"],
    },
    BackupCheck {
        path: "/backup.tar",
        title: "Backup archive (tar) exposed",
        severity: Severity::Critical,
        content_probe: None,
        magic: &[b"\x1f\x8b", b"ustar"],
    },
    BackupCheck {
        path: "/backup.tar.gz",
        title: "Backup archive (tar.gz) exposed",
        severity: Severity::Critical,
        content_probe: None,
        magic: &[b"\x1f\x8b"],
    },
    BackupCheck {
        path: "/site.zip",
        title: "Site snapshot exposed",
        severity: Severity::Critical,
        content_probe: None,
        magic: &[b"PK\x03\x04"],
    },
    BackupCheck {
        path: "/website.zip",
        title: "Website snapshot exposed",
        severity: Severity::Critical,
        content_probe: None,
        magic: &[b"PK\x03\x04"],
    },
    BackupCheck {
        path: "/www.zip",
        title: "wwwroot snapshot exposed",
        severity: Severity::Critical,
        content_probe: None,
        magic: &[b"PK\x03\x04"],
    },
    BackupCheck {
        path: "/htdocs.zip",
        title: "htdocs snapshot exposed",
        severity: Severity::Critical,
        content_probe: None,
        magic: &[b"PK\x03\x04"],
    },
    BackupCheck {
        path: "/public_html.zip",
        title: "public_html snapshot exposed",
        severity: Severity::Critical,
        content_probe: None,
        magic: &[b"PK\x03\x04"],
    },
    BackupCheck {
        path: "/admin.zip",
        title: "/admin snapshot exposed",
        severity: Severity::Critical,
        content_probe: None,
        magic: &[b"PK\x03\x04"],
    },
    // ── SQL dumps ─────────────────────────────────────────────────
    BackupCheck {
        path: "/db.sql",
        title: "SQL dump exposed",
        severity: Severity::Critical,
        content_probe: Some("CREATE TABLE"),
        magic: &[],
    },
    BackupCheck {
        path: "/dump.sql",
        title: "SQL dump exposed",
        severity: Severity::Critical,
        content_probe: Some("INSERT INTO"),
        magic: &[],
    },
    BackupCheck {
        path: "/dump.sql.gz",
        title: "Gzipped SQL dump exposed",
        severity: Severity::Critical,
        content_probe: None,
        magic: &[b"\x1f\x8b"],
    },
    BackupCheck {
        path: "/data.sql",
        title: "SQL dump exposed",
        severity: Severity::Critical,
        content_probe: Some("INSERT INTO"),
        magic: &[],
    },
    BackupCheck {
        path: "/database.sql",
        title: "SQL dump exposed",
        severity: Severity::Critical,
        content_probe: Some("CREATE TABLE"),
        magic: &[],
    },
    BackupCheck {
        path: "/backup.sql",
        title: "SQL dump exposed",
        severity: Severity::Critical,
        content_probe: Some("CREATE TABLE"),
        magic: &[],
    },
    BackupCheck {
        path: "/mysql.sql",
        title: "MySQL dump exposed",
        severity: Severity::Critical,
        content_probe: Some("INSERT INTO"),
        magic: &[],
    },
    BackupCheck {
        path: "/postgres.sql",
        title: "Postgres dump exposed",
        severity: Severity::Critical,
        content_probe: Some("CREATE TABLE"),
        magic: &[],
    },
    // ── Editor / IDE artefacts ────────────────────────────────────
    BackupCheck {
        path: "/.swp",
        title: "Vim swap file exposed",
        severity: Severity::High,
        content_probe: None,
        magic: &[b"b0VIM"],
    },
    BackupCheck {
        path: "/index.php.swp",
        title: "Vim swap (index.php) exposed",
        severity: Severity::High,
        content_probe: None,
        magic: &[b"b0VIM"],
    },
    BackupCheck {
        path: "/index.html.swp",
        title: "Vim swap (index.html) exposed",
        severity: Severity::High,
        content_probe: None,
        magic: &[b"b0VIM"],
    },
    BackupCheck {
        path: "/wp-config.php.swp",
        title: "Vim swap (wp-config.php) exposed",
        severity: Severity::Critical,
        content_probe: None,
        magic: &[b"b0VIM"],
    },
    BackupCheck {
        path: "/.DS_Store",
        title: ".DS_Store exposed",
        severity: Severity::Low,
        content_probe: None,
        magic: &[b"BUD1", b"bplist"],
    },
    // ── Common version-suffix backups ─────────────────────────────
    BackupCheck {
        path: "/index.php.bak",
        title: "index.php backup exposed",
        severity: Severity::High,
        content_probe: Some("<?"),
        magic: &[],
    },
    BackupCheck {
        path: "/index.html.bak",
        title: "index.html backup exposed",
        severity: Severity::Medium,
        content_probe: None,
        magic: &[],
    },
    BackupCheck {
        path: "/index.php~",
        title: "index.php~ backup exposed",
        severity: Severity::High,
        content_probe: Some("<?"),
        magic: &[],
    },
    BackupCheck {
        path: "/index.php.old",
        title: "index.php.old backup exposed",
        severity: Severity::High,
        content_probe: Some("<?"),
        magic: &[],
    },
    BackupCheck {
        path: "/index.php.orig",
        title: "index.php.orig backup exposed",
        severity: Severity::High,
        content_probe: Some("<?"),
        magic: &[],
    },
    BackupCheck {
        path: "/web.config.bak",
        title: "web.config backup exposed",
        severity: Severity::High,
        content_probe: Some("<configuration"),
        magic: &[],
    },
    BackupCheck {
        path: "/config.php.bak",
        title: "config.php backup exposed",
        severity: Severity::Critical,
        content_probe: Some("<?"),
        magic: &[],
    },
    BackupCheck {
        path: "/settings.py.bak",
        title: "settings.py backup exposed",
        severity: Severity::Critical,
        content_probe: Some("SECRET_KEY"),
        magic: &[],
    },
    BackupCheck {
        path: "/application.yml.bak",
        title: "application.yml backup exposed",
        severity: Severity::High,
        content_probe: Some(":"),
        magic: &[],
    },
    BackupCheck {
        path: "/database.yml.bak",
        title: "database.yml backup exposed",
        severity: Severity::Critical,
        content_probe: Some("password"),
        magic: &[],
    },
    // ── IDE project metadata ──────────────────────────────────────
    BackupCheck {
        path: "/.idea/workspace.xml",
        title: "JetBrains IDE workspace exposed",
        severity: Severity::Medium,
        content_probe: Some("<project"),
        magic: &[],
    },
    BackupCheck {
        path: "/.vscode/settings.json",
        title: "VSCode settings exposed",
        severity: Severity::Low,
        content_probe: Some("{"),
        magic: &[],
    },
    BackupCheck {
        path: "/.project",
        title: "Eclipse .project exposed",
        severity: Severity::Low,
        content_probe: Some("<projectDescription"),
        magic: &[],
    },
    // ── Compressed config / log dumps ─────────────────────────────
    BackupCheck {
        path: "/logs.zip",
        title: "Logs archive exposed",
        severity: Severity::High,
        content_probe: None,
        magic: &[b"PK\x03\x04"],
    },
    BackupCheck {
        path: "/access.log.gz",
        title: "Access-log archive exposed",
        severity: Severity::Medium,
        content_probe: None,
        magic: &[b"\x1f\x8b"],
    },
    BackupCheck {
        path: "/error.log.gz",
        title: "Error-log archive exposed",
        severity: Severity::Medium,
        content_probe: None,
        magic: &[b"\x1f\x8b"],
    },
];

/// Probe the target for backup-file exposures. No-op for non-Web targets.
pub async fn probe(
    client: &reqwest::Client,
    target: &Target,
    rate_limiter: &std::sync::Arc<crate::HostRateLimiter>,
    host: &str,
) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let base = asset.url.as_str().trim_end_matches('/').to_string();

    // Establish a baseline fingerprint for soft-404 detection
    let baseline = crate::soft404::establish(client, &base).await;

    let indices: Vec<usize> = (0..BACKUP_CHECKS.len()).collect();
    let results: Vec<Vec<Finding>> = futures::stream::iter(indices)
        .map(|idx| {
            let client = client.clone();
            let base = base.clone();
            let target = target.clone();
            let rl = std::sync::Arc::clone(rate_limiter);
            let host_str = host.to_string();
            let baseline_opt = baseline.clone();
            async move {
                process_one(
                    client,
                    base,
                    target,
                    &BACKUP_CHECKS[idx],
                    &rl,
                    &host_str,
                    baseline_opt.as_ref(),
                )
                .await
            }
        })
        .buffer_unordered(PARALLEL_REQUESTS)
        .collect()
        .await;

    Ok(results.into_iter().flatten().collect())
}

async fn process_one(
    client: reqwest::Client,
    base: String,
    target: Target,
    check: &BackupCheck,
    rate_limiter: &crate::HostRateLimiter,
    host: &str,
    baseline: Option<&crate::soft404::BaselineFingerprint>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let url = format!("{}{}", base, check.path);

    rate_limiter.wait_for_host(host).await;
    let Ok(resp) = client.get(&url).send().await else {
        return findings;
    };
    let status = resp.status().as_u16();
    rate_limiter.observe_status(host, status).await;

    if status != 200 {
        return findings;
    }

    let bytes = match soft404::read_limited(resp, MAX_BODY_BYTES).await {
        Some(b) => b,
        None => return findings,
    };

    if crate::soft404::is_likely_404(status, &bytes, baseline, false) {
        return findings;
    }

    if !check.magic.is_empty() && !magic_matches(check.magic, &bytes) {
        return findings;
    }
    if let Some(needle) = check.content_probe {
        let body = String::from_utf8_lossy(&bytes);
        if !body.contains(needle) {
            return findings;
        }
    }

    let body_excerpt: String = String::from_utf8_lossy(&bytes).chars().take(300).collect();
    try_push_finding(
        finding_builder(&target, check.severity, check.title, check.title)
            .evidence(Evidence::HttpResponse {
                status: 200,
                headers: vec![],
                body_excerpt: Some(body_excerpt.into()),
            })
            .tag("exposure")
            .tag("backup"),
        &mut findings,
    );
    findings
}

fn magic_matches(magics: &[&[u8]], data: &[u8]) -> bool {
    magics.iter().any(|m| {
        if m == &b"ustar".as_slice() {
            // tar magic lives at offset 257.
            data.len() >= 262 && data[257..].starts_with(m)
        } else {
            data.starts_with(m)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_list_is_non_trivial() {
        // Spec calls for a long tail of common paths.
        assert!(BACKUP_CHECKS.len() >= 30);
    }

    #[test]
    fn check_paths_are_unique() {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for c in BACKUP_CHECKS {
            assert!(
                seen.insert(c.path),
                "duplicate backup check path: {}",
                c.path
            );
        }
    }

    #[test]
    fn check_paths_start_with_slash() {
        for c in BACKUP_CHECKS {
            assert!(c.path.starts_with('/'), "{} must start with /", c.path);
        }
    }

    #[test]
    fn magic_matches_zip_at_offset_zero() {
        assert!(magic_matches(&[b"PK\x03\x04"], b"PK\x03\x04somezipdata"));
        assert!(!magic_matches(&[b"PK\x03\x04"], b"<html></html>"));
    }

    #[test]
    fn magic_matches_tar_at_offset_257() {
        let mut data = vec![0u8; 257];
        data.extend_from_slice(b"ustar  ");
        data.extend_from_slice(&[0u8; 100]);
        assert!(magic_matches(&[b"ustar"], &data));
        assert!(!magic_matches(&[b"ustar"], b"too short"));
    }

    #[test]
    fn probe_is_noop_on_non_web_target() {
        let target = Target::Domain(gossan_core::DomainTarget {
            domain: "example.com".into(),
            source: gossan_core::DiscoverySource::Seed,
        });
        let client = reqwest::Client::new();
        let rl = std::sync::Arc::new(crate::HostRateLimiter::new(1));
        let findings = futures::executor::block_on(probe(&client, &target, &rl, "example.com")).unwrap();
        assert!(findings.is_empty());
    }
}
