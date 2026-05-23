//! NVD CVE lookup via local SQLite cache.
//!
//! Queries a locally-synced copy of the NIST National Vulnerability Database
//! using the same schema as the `nvd_cve` tool. The database must be synced
//! first via `gossan nvd-sync` (or the `nvd_cve` CLI).
//!
//! # Setup
//!
//! ```bash
//! gossan nvd-sync
//! ```
//!
//! The sync downloads NVD JSON feeds into `~/.cache/nvd/nvd.sqlite3`
//! (XDG default, overridable via `--nvd-db` / `NVD_DB_PATH`).
//!
//! Once synced, every portscan also queries the NVD cache for CVE matches.
//! NVD findings carry the `nvd` tag so they can be filtered independently.

use gossan_core::{ServiceTarget, Target};
use secfinding::{Evidence, Finding, Severity};
use std::path::PathBuf;
use std::sync::OnceLock;

static NVD: OnceLock<NvdDatabase> = OnceLock::new();

/// NVD CVE database backed by a local SQLite cache.
pub struct NvdDatabase {
    db_path: String,
}

impl NvdDatabase {
    fn new(db_path: PathBuf) -> Self {
        Self {
            db_path: db_path.to_string_lossy().to_string(),
        }
    }

    pub fn is_available(&self) -> bool {
        std::path::Path::new(&self.db_path).exists()
    }

    fn conn(&self) -> Result<rusqlite::Connection, rusqlite::Error> {
        rusqlite::Connection::open(&self.db_path)
    }

    pub fn search_banner(&self, banner: &str, svc: &ServiceTarget) -> Vec<Finding> {
        if !self.is_available() {
            return Vec::new();
        }
        let keywords = extract_search_terms(banner);
        let mut cve_ids: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let conn = match self.conn() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        for kw in &keywords {
            if let Ok(ids) = search_description(&conn, kw) {
                for id in ids {
                    if seen.insert(id.clone()) {
                        cve_ids.push(id);
                    }
                }
            }
        }

        let mut findings = Vec::new();
        for cve_id in &cve_ids {
            if let Some(finding) = self.cve_id_to_finding(cve_id, &conn, svc) {
                findings.push(finding);
            }
        }
        findings
    }

    fn cve_id_to_finding(
        &self,
        cve_id: &str,
        conn: &rusqlite::Connection,
        svc: &ServiceTarget,
    ) -> Option<Finding> {
        let data: String = conn
            .query_row(
                "SELECT data FROM cve WHERE id = ?1",
                rusqlite::params![cve_id],
                |row| row.get(0),
            )
            .ok()?;

        let parsed: serde_json::Value = serde_json::from_str(&data).ok()?;
        let description = parsed
            .pointer("/description/description_data")
            .and_then(|v| v.as_array())
            .and_then(|arr| {
                arr.iter()
                    .find(|d| d.get("lang").and_then(|l| l.as_str()) == Some("en"))
                    .and_then(|d| d.get("value").and_then(|v| v.as_str()))
            })
            .unwrap_or("")
            .to_string();

        if description.is_empty() {
            return None;
        }

        let severity = guess_severity(&description);
        let target = Target::Service(svc.clone());

        let builder = crate::finding_builder(
            &target,
            severity,
            format!(
                "NVD: {} — {}",
                cve_id,
                description.split('.').next().unwrap_or("")
            ),
            &description.chars().take(200).collect::<String>(),
        )
        .cve(cve_id)
        .confidence(match severity {
            Severity::Critical => 0.9,
            Severity::High => 0.7,
            Severity::Medium => 0.5,
            Severity::Low => 0.3,
            Severity::Info => 0.1,
            _ => 0.5,
        })
        .evidence(Evidence::Banner {
            raw: description.chars().take(120).collect::<String>().into(),
        })
        .tag("cve")
        .tag("nvd")
        .tag("version-disclosure");

        builder.build().ok()
    }
}

pub fn init(db_path: Option<PathBuf>) {
    let path = db_path.unwrap_or_else(default_db_path);
    let _ = NVD.set(NvdDatabase::new(path));
}

pub fn try_search(banner: &str, svc: &ServiceTarget) -> Vec<Finding> {
    match NVD.get() {
        Some(nvd) if nvd.is_available() => nvd.search_banner(banner, svc),
        _ => Vec::new(),
    }
}

fn default_db_path() -> PathBuf {
    let mut path = if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        PathBuf::from(xdg)
    } else if let Some(home) = dirs_next().or_else(|| std::env::var("HOME").ok().map(PathBuf::from))
    {
        home.join(".cache")
    } else {
        std::env::temp_dir()
    };
    path.push("nvd");
    path.push("nvd.sqlite3");
    path
}

fn dirs_next() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

fn search_description(
    conn: &rusqlite::Connection,
    text: &str,
) -> Result<Vec<String>, rusqlite::Error> {
    let mut stmt = conn.prepare("SELECT id FROM cve WHERE description LIKE '%' || ?1 || '%'")?;
    let ids = stmt
        .query_map(rusqlite::params![text], |row| row.get(0))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(ids)
}

fn extract_search_terms(banner: &str) -> Vec<String> {
    let lower = banner.to_lowercase();
    let mut terms: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let mut push = |t: String| {
        if !t.is_empty() && seen.insert(t.clone()) {
            terms.push(t);
        }
    };

    push(clean_banner(banner));

    if lower.contains("openssh") {
        push("openssh".into());
        if let Some(v) = lower.split("openssh_").nth(1) {
            let v = v
                .split(|c: char| !c.is_alphanumeric() && c != '.')
                .next()
                .unwrap_or("");
            if !v.is_empty() {
                push(format!("openssh {v}"));
                let dotted = v
                    .chars()
                    .map(|c| if c == '_' { '.' } else { c })
                    .collect::<String>();
                push(format!("openssh {dotted}"));
            }
        }
    }

    if lower.contains("apache") {
        push("apache".into());
        push("apache http server".into());
        if let Some(v) = lower.split("apache/").nth(1) {
            let v = v.split_whitespace().next().unwrap_or("");
            if !v.is_empty() {
                push(format!("apache http server {v}"));
            }
        }
    }

    if lower.contains("nginx") {
        push("nginx".into());
        if let Some(v) = lower.split("nginx/").nth(1) {
            let v = v.split_whitespace().next().unwrap_or("");
            if !v.is_empty() {
                push(format!("nginx {v}"));
            }
        }
    }

    if lower.contains("openssl") {
        push("openssl".into());
        if let Some(v) = lower.split("openssl/").nth(1) {
            let v = v.split_whitespace().next().unwrap_or("");
            if !v.is_empty() {
                push(format!("openssl {v}"));
            }
        }
    }

    if lower.contains("iis") || lower.contains("microsoft-iis") {
        push("iis".into());
        push("microsoft iis".into());
    }

    if lower.contains("vsftpd") {
        push("vsftpd".into());
    }
    if lower.contains("proftpd") {
        push("proftpd".into());
    }
    if lower.contains("exim") {
        push("exim".into());
    }
    if lower.contains("dovecot") {
        push("dovecot".into());
    }
    if lower.contains("postfix") {
        push("postfix".into());
    }
    if lower.contains("redis") || lower.contains("+pong") {
        push("redis".into());
    }
    if lower.contains("mysql") || lower.contains("mariadb") {
        push("mysql".into());
        push("mariadb".into());
    }
    if lower.contains("postgresql") || lower.contains("pgsql") {
        push("postgresql".into());
    }
    if lower.contains("mongodb") || lower.contains("ismaster") {
        push("mongodb".into());
    }
    if lower.contains("elasticsearch")
        || lower.contains("lucene")
        || lower.contains("you know, for search")
    {
        push("elasticsearch".into());
    }
    if lower.contains("docker") {
        push("docker".into());
    }
    if lower.contains("kubernetes") {
        push("kubernetes".into());
    }
    if lower.contains("memcached") {
        push("memcached".into());
    }
    if lower.contains("tomcat") {
        push("tomcat".into());
    }
    if lower.contains("jetty") {
        push("jetty".into());
    }
    if lower.contains("php/") || lower.contains("php ") {
        push("php".into());
        if let Some(v) = lower.split("php/").nth(1) {
            let v = v.split_whitespace().next().unwrap_or("");
            if !v.is_empty() {
                push(format!("php {v}"));
            }
        }
    }
    if lower.contains("wordpress") || lower.contains("wp-") {
        push("wordpress".into());
    }
    if lower.contains("drupal") {
        push("drupal".into());
    }
    if lower.contains("joomla") {
        push("joomla".into());
    }

    for line in banner.lines() {
        let lc = line.to_lowercase();
        if lc.starts_with("server:") {
            let val = line
                .trim_start_matches("Server:")
                .trim_start_matches("server:")
                .trim();
            if !val.is_empty() {
                push(val.to_string());
                if let Some(first) = val.split('/').next() {
                    push(first.to_string());
                }
            }
        }
    }

    terms
}

fn clean_banner(banner: &str) -> String {
    banner
        .chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace() || *c == '/' || *c == '.' || *c == '-')
        .take(100)
        .collect::<String>()
        .trim()
        .to_lowercase()
}

fn guess_severity(description: &str) -> Severity {
    let lower = description.to_lowercase();
    if lower.contains("critical")
        || lower.contains("remote code execution")
        || lower.contains("rce")
        || lower.contains("arbitrary code")
        || lower.contains("unauthenticated")
        || lower.contains("buffer overflow")
        || lower.contains("heap overflow")
        || lower.contains("use-after-free")
        || lower.contains("sandbox escape")
        || lower.contains("privilege escalation")
    {
        Severity::Critical
    } else if lower.contains("high")
        || lower.contains("denial of service")
        || lower.contains("dos")
        || lower.contains("information disclosure")
        || lower.contains("path traversal")
        || lower.contains("sql injection")
        || lower.contains("cross-site scripting")
        || lower.contains("xss")
        || lower.contains("memory corruption")
        || lower.contains("out-of-bounds")
    {
        Severity::High
    } else if lower.contains("medium")
        || lower.contains("spoofing")
        || lower.contains("csrf")
        || lower.contains("bypass")
    {
        Severity::Medium
    } else if lower.contains("low") || lower.contains("deprecated") {
        Severity::Low
    } else {
        Severity::Medium
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ssh_keywords() {
        let terms = extract_search_terms("SSH-2.0-OpenSSH_8.0");
        assert!(terms.iter().any(|t| t.contains("openssh")));
        assert!(terms.iter().any(|t| t.contains("openssh 8.0")));
    }

    #[test]
    fn test_extract_apache_keywords() {
        let terms = extract_search_terms("HTTP/1.1 200 OK\r\nServer: Apache/2.4.49");
        assert!(terms.iter().any(|t| t.contains("apache http server")));
    }

    #[test]
    fn test_extract_nginx_keywords() {
        let terms = extract_search_terms("nginx/1.24.0");
        assert!(terms.iter().any(|t| t.contains("nginx 1.24")));
    }

    #[test]
    fn test_guess_severity_critical() {
        assert_eq!(
            guess_severity("Remote Code Execution vulnerability"),
            Severity::Critical
        );
        assert_eq!(
            guess_severity("heap overflow in parser"),
            Severity::Critical
        );
    }

    #[test]
    fn test_guess_severity_high() {
        assert_eq!(
            guess_severity("Cross-site Scripting vulnerability"),
            Severity::High
        );
        assert_eq!(guess_severity("Denial of Service"), Severity::High);
    }

    #[test]
    fn test_server_header_extraction() {
        let terms = extract_search_terms("HTTP/1.1 200 OK\r\nServer: CouchDB/3.2.1\r\n");
        assert!(terms.iter().any(|t| t.contains("couchdb")));
    }
}
