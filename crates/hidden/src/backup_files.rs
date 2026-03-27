//! Backup and configuration file exposure scanner.
//!
//! Probes for common backup, swap, and configuration files left on web servers.
//! These files often contain database credentials, API keys, internal paths,
//! and architectural information that aids further compromise.
//!
//! Covers:
//!   - Editor swap/backup files (`.swp`, `~`, `.bak`, `.old`)
//!   - Configuration files (`.env`, `wp-config.php.bak`, `web.config`)
//!   - Database dumps (`dump.sql`, `database.sql`)
//!   - Archive files (`backup.tar.gz`, `backup.zip`)
//!   - Version control (`/.svn/entries`, `/.hg/dirstate`)

use gossan_core::Target;
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};

/// A backup/config file probe with expected content confirmation.
struct BackupProbe {
    /// Path to probe (relative to root).
    path: &'static str,
    /// Human-readable description of what this file is.
    description: &'static str,
    /// Severity if found.
    severity: Severity,
    /// Substring(s) expected in the response body to confirm a real finding.
    /// Empty slice means any 200 response is a finding.
    body_confirms: &'static [&'static str],
    /// Minimum body length to consider it a real file (avoids custom 404 pages).
    min_body_len: usize,
}

/// All backup and configuration file probes.
const PROBES: &[BackupProbe] = &[
    // ── Editor swap/backup files ────────────────────────────────────────────
    BackupProbe {
        path: "/index.php.bak",
        description: "PHP backup file — may contain database credentials and internal logic.",
        severity: Severity::High,
        body_confirms: &["<?php", "<?="],
        min_body_len: 20,
    },
    BackupProbe {
        path: "/index.php~",
        description: "Editor backup of index.php — may expose source code.",
        severity: Severity::High,
        body_confirms: &["<?php", "<?="],
        min_body_len: 20,
    },
    BackupProbe {
        path: "/index.php.swp",
        description: "Vim swap file — contains partial source code.",
        severity: Severity::Medium,
        body_confirms: &["b0VIM"],
        min_body_len: 100,
    },
    BackupProbe {
        path: "/index.php.old",
        description: "Old copy of index.php — may contain outdated credentials.",
        severity: Severity::High,
        body_confirms: &["<?php", "<?="],
        min_body_len: 20,
    },
    // ── WordPress config backups ────────────────────────────────────────────
    BackupProbe {
        path: "/wp-config.php.bak",
        description: "WordPress config backup — contains DB credentials and auth salts.",
        severity: Severity::Critical,
        body_confirms: &["DB_PASSWORD", "DB_NAME", "AUTH_KEY"],
        min_body_len: 100,
    },
    BackupProbe {
        path: "/wp-config.php.old",
        description: "Old WordPress config — database credentials likely exposed.",
        severity: Severity::Critical,
        body_confirms: &["DB_PASSWORD", "DB_NAME"],
        min_body_len: 100,
    },
    BackupProbe {
        path: "/wp-config.php~",
        description: "Editor backup of WordPress config.",
        severity: Severity::Critical,
        body_confirms: &["DB_PASSWORD", "DB_NAME"],
        min_body_len: 100,
    },
    BackupProbe {
        path: "/wp-config.php.save",
        description: "Nano save file of WordPress config.",
        severity: Severity::Critical,
        body_confirms: &["DB_PASSWORD", "DB_NAME"],
        min_body_len: 100,
    },
    // ── Configuration files ────────────────────────────────────────────────
    BackupProbe {
        path: "/.env",
        description: "Dotenv file — application secrets, API keys, database URLs.",
        severity: Severity::Critical,
        body_confirms: &["="],
        min_body_len: 10,
    },
    BackupProbe {
        path: "/.env.production",
        description: "Production dotenv — live credentials.",
        severity: Severity::Critical,
        body_confirms: &["="],
        min_body_len: 10,
    },
    BackupProbe {
        path: "/.env.staging",
        description: "Staging dotenv — may contain production-adjacent credentials.",
        severity: Severity::High,
        body_confirms: &["="],
        min_body_len: 10,
    },
    BackupProbe {
        path: "/.env.backup",
        description: "Backed-up dotenv file.",
        severity: Severity::Critical,
        body_confirms: &["="],
        min_body_len: 10,
    },
    BackupProbe {
        path: "/web.config",
        description: "IIS/ASP.NET web.config — may contain connection strings and auth settings.",
        severity: Severity::High,
        body_confirms: &["<configuration", "connectionString"],
        min_body_len: 50,
    },
    BackupProbe {
        path: "/config.php",
        description: "PHP config file — may contain database credentials.",
        severity: Severity::High,
        body_confirms: &["<?php"],
        min_body_len: 20,
    },
    BackupProbe {
        path: "/configuration.php",
        description: "Joomla config — database credentials and secret.",
        severity: Severity::Critical,
        body_confirms: &["JConfig", "password"],
        min_body_len: 50,
    },
    // ── Database dumps ─────────────────────────────────────────────────────
    BackupProbe {
        path: "/dump.sql",
        description: "SQL dump — full database contents including user tables.",
        severity: Severity::Critical,
        body_confirms: &["INSERT INTO", "CREATE TABLE", "mysqldump"],
        min_body_len: 100,
    },
    BackupProbe {
        path: "/database.sql",
        description: "Database export — credentials and user data.",
        severity: Severity::Critical,
        body_confirms: &["INSERT INTO", "CREATE TABLE"],
        min_body_len: 100,
    },
    BackupProbe {
        path: "/backup.sql",
        description: "SQL backup — full table contents.",
        severity: Severity::Critical,
        body_confirms: &["INSERT INTO", "CREATE TABLE"],
        min_body_len: 100,
    },
    BackupProbe {
        path: "/db.sql",
        description: "Database dump.",
        severity: Severity::Critical,
        body_confirms: &["INSERT INTO", "CREATE TABLE"],
        min_body_len: 100,
    },
    // ── Archive files ──────────────────────────────────────────────────────
    BackupProbe {
        path: "/backup.zip",
        description: "ZIP backup archive — may contain source code and config files.",
        severity: Severity::Critical,
        body_confirms: &[],
        min_body_len: 100,
    },
    BackupProbe {
        path: "/backup.tar.gz",
        description: "Tarball backup — likely contains full application source.",
        severity: Severity::Critical,
        body_confirms: &[],
        min_body_len: 100,
    },
    // ── Version control ────────────────────────────────────────────────────
    BackupProbe {
        path: "/.svn/entries",
        description: "Subversion metadata — reveals file listing and repo structure.",
        severity: Severity::High,
        body_confirms: &["dir", "svn"],
        min_body_len: 10,
    },
    BackupProbe {
        path: "/.hg/dirstate",
        description: "Mercurial dirstate — reveals tracked files.",
        severity: Severity::High,
        body_confirms: &[],
        min_body_len: 20,
    },
    // ── server-generated files ──────────────────────────────────────────────
    BackupProbe {
        path: "/phpinfo.php",
        description: "phpinfo() output — exposes PHP version, extensions, paths, env vars.",
        severity: Severity::Medium,
        body_confirms: &["phpinfo()", "PHP Version", "php.ini"],
        min_body_len: 200,
    },
    BackupProbe {
        path: "/.DS_Store",
        description: "macOS directory metadata — reveals file listing.",
        severity: Severity::Low,
        body_confirms: &[],
        min_body_len: 8,
    },
    BackupProbe {
        path: "/crossdomain.xml",
        description: "Flash cross-domain policy — may allow cross-origin data access.",
        severity: Severity::Medium,
        body_confirms: &["allow-access-from", "cross-domain-policy"],
        min_body_len: 30,
    },
    BackupProbe {
        path: "/.dockerenv",
        description: "Docker environment marker — confirms containerized deployment.",
        severity: Severity::Info,
        body_confirms: &[],
        min_body_len: 0,
    },
];

/// Probe for backup and configuration files on a web target.
///
/// Sends a GET request for each path in the probe list. A finding is generated
/// when the server responds with HTTP 200 and the body either:
///   1. Contains at least one of the expected confirmation strings, OR
///   2. Has no confirmation strings required but meets the minimum body length.
///
/// # Returns
///
/// A vector of `Finding`s for each confirmed backup/config file.
pub async fn probe(client: &Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let asset = match target {
        Target::Web(asset) => asset,
        _ => return Ok(vec![]),
    };

    let base = asset.url.as_str().trim_end_matches('/');
    let mut findings = Vec::new();

    for p in PROBES {
        let url = format!("{}{}", base, p.path);

        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };

        let status = resp.status().as_u16();
        if status != 200 {
            continue;
        }

        // Check Content-Type: skip HTML error pages for binary probes
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let is_archive = p.path.ends_with(".zip")
            || p.path.ends_with(".tar.gz")
            || p.path.ends_with(".DS_Store")
            || p.path.ends_with(".hg/dirstate");

        if is_archive && content_type.contains("text/html") {
            continue; // custom 404 page
        }

        let body = match resp.text().await {
            Ok(b) => b,
            Err(_) => continue,
        };

        if body.len() < p.min_body_len {
            continue;
        }

        // Body confirmation check
        if !p.body_confirms.is_empty()
            && !p.body_confirms.iter().any(|s| body.contains(s))
        {
            continue;
        }

        findings.push(
            Finding::builder("hidden", target.domain().unwrap_or("?"), p.severity)
                .title(format!("Backup/config file exposed: {}", p.path))
                .detail(format!(
                    "{} ({} bytes accessible at {})",
                    p.description,
                    body.len(),
                    url
                ))
                .evidence(Evidence::HttpResponse {
                    status,
                    headers: vec![("content-type".into(), content_type.clone())],
                    body_excerpt: Some(body.chars().take(200).collect()),
                })
                .tag("backup")
                .tag("exposure")
                .tag("config")
                .build()
                .expect("finding builder: required fields are set"),
        );
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_probe_paths_start_with_slash() {
        for probe in PROBES {
            assert!(
                probe.path.starts_with('/'),
                "probe path must start with /: {}",
                probe.path
            );
        }
    }

    #[test]
    fn probe_count_is_substantial() {
        assert!(
            PROBES.len() >= 25,
            "should have 25+ backup/config probes, got {}",
            PROBES.len()
        );
    }

    #[test]
    fn critical_probes_have_body_confirms() {
        for probe in PROBES {
            if probe.severity == Severity::Critical && !probe.path.ends_with(".zip") && !probe.path.ends_with(".tar.gz") {
                assert!(
                    !probe.body_confirms.is_empty(),
                    "critical probe {} should have body confirmation strings to prevent FPs",
                    probe.path
                );
            }
        }
    }

    #[test]
    fn no_duplicate_paths() {
        let mut seen = std::collections::HashSet::new();
        for probe in PROBES {
            assert!(
                seen.insert(probe.path),
                "duplicate probe path: {}",
                probe.path
            );
        }
    }

    #[test]
    fn descriptions_are_nonempty() {
        for probe in PROBES {
            assert!(
                !probe.description.is_empty(),
                "probe {} has empty description",
                probe.path
            );
        }
    }
}
