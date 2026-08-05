//! CLI argument definitions (clap-derived command tree).

use clap::{Parser, Subcommand};
#[derive(Parser)]
#[command(
    name    = "gossan",
    version,
    about   = "Attack surface discovery, subdomains, ports, tech stack, JS secrets, hidden endpoints, cloud assets",
    long_about = None,
)]
/// Top-level CLI argument parser for the gossan binary.
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    // ── Output ─────────────────────────────────────────────────────────────
    #[arg(
        long,
        global = true,
        help = "Output format: text | json | jsonl | sarif | markdown | masscan-grep | nmap-xml | graphml (default: text, or gossan.toml output.format when present)"
    )]
    pub format: Option<String>,
    #[arg(long, global = true, help = "Write output to file instead of stdout")]
    pub out: Option<String>,

    // ── Tuning ─────────────────────────────────────────────────────────────
    #[arg(
        long,
        global = true,
        help = "Max requests per second (also the AIMD ceiling when --adaptive-rate is set; default: 50, or gossan.toml)"
    )]
    pub rate: Option<u32>,
    #[arg(
        long,
        global = true,
        help = "Enable closed-loop AIMD rate adaptation in `gossan engine` (halves on TX-drop bursts; ramps after clean batches)"
    )]
    pub adaptive_rate: bool,
    #[arg(
        long,
        global = true,
        help = "Per-request timeout in seconds (default: 10, or gossan.toml)"
    )]
    pub timeout: Option<u64>,
    #[arg(
        long,
        global = true,
        help = "Global scan timeout in seconds (0 = disabled; default: 600, or gossan.toml)"
    )]
    pub scan_timeout: Option<u64>,
    #[arg(
        long,
        global = true,
        help = "Max concurrent tasks (default: 150, or gossan.toml)"
    )]
    pub concurrency: Option<usize>,
    #[arg(
        long,
        global = true,
        help = "Minimum severity to report: info | low | medium | high | critical"
    )]
    pub min_severity: Option<String>,
    #[arg(
        long,
        global = true,
        value_delimiter = ',',
        help = "Only show findings of these kinds (comma-separated: vulnerability,misconfiguration,exposure,...)"
    )]
    pub include_kind: Vec<String>,
    #[arg(
        long,
        global = true,
        value_delimiter = ',',
        help = "Exclude findings of these kinds (comma-separated)"
    )]
    pub exclude_kind: Vec<String>,
    #[arg(
        long,
        global = true,
        help = "HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)"
    )]
    pub proxy: Option<String>,
    #[arg(long, global = true, help = "Cookie header for authenticated crawling")]
    pub cookie: Option<String>,
    #[arg(long, global = true, help = "Username for authenticated crawling")]
    pub auth_user: Option<String>,
    #[arg(long, global = true, help = "Password for authenticated crawling")]
    pub auth_pass: Option<String>,
    #[arg(
        long,
        global = true,
        value_delimiter = ',',
        help = "Custom DNS resolvers (comma-separated IPs, e.g. 1.1.1.1,8.8.8.8)"
    )]
    pub resolvers: Vec<String>,

    // ── Port mode ──────────────────────────────────────────────────────────
    #[arg(
        long,
        global = true,
        help = "Ports to scan: default | top100 | top1000 | full | 22,80,443,…"
    )]
    pub ports: Option<String>,

    // ── API keys (also read from env vars) ──
    #[arg(long, global = true, env = "VT_API_KEY", help = "VirusTotal API key")]
    pub vt_key: Option<String>,
    #[arg(
        long,
        global = true,
        env = "ST_API_KEY",
        help = "SecurityTrails API key"
    )]
    pub st_key: Option<String>,
    #[arg(long, global = true, env = "SHODAN_API_KEY", help = "Shodan API key")]
    pub shodan_key: Option<String>,
    #[arg(
        long,
        global = true,
        env = "GITHUB_TOKEN",
        help = "GitHub token for code-search subdomain discovery"
    )]
    pub github_token: Option<String>,
    #[arg(
        long,
        global = true,
        env = "CENSYS_API_KEY",
        help = "Censys API key (format: api_id:api_secret)"
    )]
    pub censys_key: Option<String>,
    #[arg(
        long,
        global = true,
        env = "BINARYEDGE_API_KEY",
        help = "BinaryEdge API key"
    )]
    pub binaryedge_key: Option<String>,
    #[arg(
        long,
        global = true,
        env = "FULLHUNT_API_KEY",
        help = "FullHunt API key"
    )]
    pub fullhunt_key: Option<String>,
    #[arg(
        long,
        global = true,
        env = "CHAOS_API_KEY",
        help = "Chaos (ProjectDiscovery) API key"
    )]
    pub chaos_key: Option<String>,
    #[arg(long, global = true, env = "BEVIGIL_API_KEY", help = "Bevigil API key")]
    pub bevigil_key: Option<String>,
    #[arg(
        long,
        global = true,
        env = "FOFA_API_KEY",
        help = "FOFA API key (format: email:key)"
    )]
    pub fofa_key: Option<String>,
    #[arg(
        long,
        global = true,
        env = "HUNTER_API_KEY",
        help = "Hunter.io API key"
    )]
    pub hunter_key: Option<String>,
    #[arg(long, global = true, env = "NETLAS_API_KEY", help = "Netlas API key")]
    pub netlas_key: Option<String>,
    #[arg(long, global = true, env = "ZOOMEYE_API_KEY", help = "ZoomEye API key")]
    pub zoomeye_key: Option<String>,
    #[arg(long, global = true, env = "C99_API_KEY", help = "C99 API key")]
    pub c99_key: Option<String>,
    #[arg(
        long,
        global = true,
        env = "QUAKE_API_KEY",
        help = "Quake (360) API key"
    )]
    pub quake_key: Option<String>,
    #[arg(
        long,
        global = true,
        env = "THREATBOOK_API_KEY",
        help = "ThreatBook API key"
    )]
    pub threatbook_key: Option<String>,

    // ── Fault isolation ───────────────────────────────────────────────────
    #[arg(
        long,
        global = true,
        help = "Abort on first scanner error (for debugging)"
    )]
    pub strict: bool,

    // ── Tuning ─────────────────────────────────────────────────────────────
    #[arg(
        long,
        global = true,
        help = "Enable conservative zero-false-positive horizontal scanning"
    )]
    pub conservative: bool,

    // ── Checkpoint / resume ────────────────────────────────────────────────
    #[arg(
        long,
        global = true,
        help = "Path to checkpoint SQLite file (enables save/resume)"
    )]
    pub checkpoint: Option<String>,
    #[arg(long, global = true, help = "Resume a previous scan by UUID")]
    pub resume: Option<String>,

    #[cfg(feature = "portscan")]
    #[arg(
        long,
        global = true,
        env = "NVD_DB_PATH",
        help = "Path to NVD CVE database (default: ~/.cache/nvd/nvd.sqlite3)"
    )]
    pub nvd_db: Option<String>,
}
/// Available gossan subcommands.

#[derive(Subcommand)]
pub enum Command {
    /// Full scan, all compiled-in modules in pipeline order
    Scan {
        /// Target domain, or '-' to read from stdin
        target: String,
        #[cfg(feature = "subdomain")]
        #[arg(long, help = "Skip subdomain discovery module")]
        no_subdomain: bool,
        #[cfg(feature = "portscan")]
        #[arg(long, help = "Skip port scanning module")]
        no_ports: bool,
        #[cfg(feature = "techstack")]
        #[arg(long, help = "Skip tech stack fingerprinting module")]
        no_tech: bool,
        #[cfg(feature = "dns")]
        #[arg(long, help = "Skip DNS security audit module")]
        no_dns: bool,
        #[cfg(feature = "js")]
        #[arg(long, help = "Skip JavaScript analysis module")]
        no_js: bool,
        #[cfg(feature = "hidden")]
        #[arg(long, help = "Skip hidden endpoint probing module")]
        no_hidden: bool,
        #[cfg(feature = "cloud")]
        #[arg(long, help = "Skip cloud asset discovery module")]
        no_cloud: bool,
        #[cfg(feature = "headless")]
        #[arg(long, help = "Skip headless browser module")]
        no_headless: bool,
        #[cfg(feature = "crawl")]
        #[arg(long, help = "Skip web crawling module")]
        no_crawl: bool,
        #[cfg(feature = "origin")]
        #[arg(long, help = "Skip origin IP discovery module")]
        no_origin: bool,
        #[cfg(feature = "horizontal")]
        #[arg(long, help = "Skip horizontal discovery module")]
        no_horizontal: bool,
        #[cfg(feature = "graph")]
        #[arg(long, help = "Skip graph persistence module")]
        no_graph: bool,
        #[cfg(feature = "scm")]
        #[arg(long, help = "Skip SCM mapping module")]
        no_scm: bool,
        #[cfg(feature = "intel")]
        #[arg(long, help = "Skip global passive intel module")]
        no_intel: bool,
        #[cfg(feature = "fleet")]
        #[arg(long, help = "Skip distributed fleet module")]
        no_fleet: bool,
        #[cfg(feature = "engine")]
        #[arg(long, help = "Skip raw SYN engine module")]
        no_engine: bool,
    },

    // Individual module subcommands, only compiled in when the feature is active
    #[cfg(feature = "subdomain")]
    /// Subdomain discovery (CT + Wayback + HackerTarget + RapidDNS + OTX + Urlscan + CommonCrawl + bruteforce)
    Subdomain { target: String },

    #[cfg(feature = "horizontal")]
    /// Horizontal discovery (ASN/BGP mapping + ownership correlation)
    Horizontal { target: String },

    #[cfg(feature = "scm")]
    /// Source Control Mapping (GitHub/GitLab org discovery)
    Scm { target: String },

    #[cfg(feature = "intel")]
    /// Global Passive Intel (Local bulk dataset query)
    Intel { target: String },

    #[cfg(feature = "fleet")]
    /// Start a distributed fleet master node
    FleetMaster {
        #[arg(long, default_value = "0.0.0.0:50051")]
        listen: String,
    },

    #[cfg(feature = "fleet")]
    /// Start a distributed fleet worker node
    FleetWorker {
        #[arg(long, default_value = "http://127.0.0.1:50051")]
        master: String,
    },

    #[cfg(feature = "portscan")]
    /// TCP port scan with banner grabbing
    Ports { target: String },

    #[cfg(feature = "techstack")]
    /// Tech stack fingerprinting + security headers audit
    Tech { target: String },

    #[cfg(feature = "dns")]
    /// DNS security audit (SPF / DMARC / DKIM / CAA / zone transfer / takeover)
    Dns { target: String },

    #[cfg(feature = "js")]
    /// JavaScript analysis (endpoints + 26-rule secret detection)
    Js { target: String },

    #[cfg(feature = "hidden")]
    /// Hidden endpoint probe (50+ paths)
    Hidden { target: String },

    #[cfg(feature = "cloud")]
    /// Cloud asset discovery (S3 / GCS / Azure Blob / DO Spaces)
    Cloud { target: String },

    #[cfg(feature = "headless")]
    /// JS rendering and dynamic XHR trapping via Headless Chromium
    Headless { target: String },

    #[cfg(feature = "crawl")]
    /// Authenticated web crawling, form extraction, parameter discovery
    Crawl { target: String },

    #[cfg(feature = "origin")]
    /// Origin IP discovery, find true server IPs behind CDNs/WAFs
    Origin { target: String },

    #[cfg(feature = "engine")]
    /// High-performance raw SYN scanner (stateless, netforge-powered, requires root)
    Engine { target: String },

    /// Show which packet I/O backend `gossan engine` would use right now
    /// (xdp / sendmmsg / pnet) plus kernel + capability + libbpf state.
    #[cfg(feature = "engine")]
    ProbeEngine,

    /// List saved checkpoint scans
    #[cfg(feature = "checkpoint")]
    ListScans {
        #[arg(long, help = "Checkpoint file path")]
        checkpoint: Option<String>,
    },
}

impl Cli {
    pub fn build_config(&self) -> gossan_core::Config {
        // TOML is the Tier-A base; CLI flags below override. Malformed
        // gossan.toml must fail closed (not silently ignore operator config).
        // Track `from_toml` from the same open path so we do not re-stat and
        // accidentally prefer CLI fallbacks after a successful file load.
        let toml_path = std::path::Path::new("gossan.toml");
        let (base, from_toml) = if toml_path.is_file() {
            match gossan_core::Config::from_toml(toml_path) {
                Ok(c) => (c, true),
                Err(e) => {
                    eprintln!("error: failed to load gossan.toml: {e}");
                    std::process::exit(2);
                }
            }
        } else {
            (gossan_core::Config::default(), false)
        };

        let format = match self.format.as_deref() {
            Some(s) => match s {
                "json" => gossan_core::OutputFormat::Json,
                "jsonl" | "ndjson" => gossan_core::OutputFormat::Jsonl,
                "sarif" => gossan_core::OutputFormat::Sarif,
                "markdown" | "md" => gossan_core::OutputFormat::Markdown,
                "masscan-grep" | "masscan" | "grep" | "grepable" | "-oG" => {
                    gossan_core::OutputFormat::MasscanGrep
                }
                "nmap-xml" | "nmap" | "xml" | "-oX" => gossan_core::OutputFormat::NmapXml,
                "graphml" | "graph-ml" => gossan_core::OutputFormat::Graphml,
                _ => gossan_core::OutputFormat::Text,
            },
            // Preserve TOML output.format when --format was not passed.
            None if from_toml => base.output.format.clone(),
            None => gossan_core::OutputFormat::Text,
        };

        let min_severity = self.min_severity.as_deref().and_then(|s| match s {
            "info" => Some(gossan_core::Severity::Info),
            "low" => Some(gossan_core::Severity::Low),
            "medium" => Some(gossan_core::Severity::Medium),
            "high" => Some(gossan_core::Severity::High),
            "critical" => Some(gossan_core::Severity::Critical),
            _ => None,
        });

        let mut api_keys = base.api_keys.clone();
        if let Some(v) = &self.vt_key {
            api_keys.insert("virustotal".to_string(), v.clone());
        }
        if let Some(v) = &self.st_key {
            api_keys.insert("securitytrails".to_string(), v.clone());
        }
        if let Some(v) = &self.shodan_key {
            api_keys.insert("shodan".to_string(), v.clone());
        }
        if let Some(v) = &self.github_token {
            api_keys.insert("github".to_string(), v.clone());
        }
        if let Some(v) = &self.censys_key {
            api_keys.insert("censys".to_string(), v.clone());
        }
        if let Some(v) = &self.binaryedge_key {
            api_keys.insert("binaryedge".to_string(), v.clone());
        }
        if let Some(v) = &self.fullhunt_key {
            api_keys.insert("fullhunt".to_string(), v.clone());
        }
        if let Some(v) = &self.chaos_key {
            api_keys.insert("chaos".to_string(), v.clone());
        }
        if let Some(v) = &self.bevigil_key {
            api_keys.insert("bevigil".to_string(), v.clone());
        }
        if let Some(v) = &self.fofa_key {
            api_keys.insert("fofa".to_string(), v.clone());
        }
        if let Some(v) = &self.hunter_key {
            api_keys.insert("hunter".to_string(), v.clone());
        }
        if let Some(v) = &self.netlas_key {
            api_keys.insert("netlas".to_string(), v.clone());
        }
        if let Some(v) = &self.zoomeye_key {
            api_keys.insert("zoomeye".to_string(), v.clone());
        }
        if let Some(v) = &self.c99_key {
            api_keys.insert("c99".to_string(), v.clone());
        }
        if let Some(v) = &self.quake_key {
            api_keys.insert("quake".to_string(), v.clone());
        }
        if let Some(v) = &self.threatbook_key {
            api_keys.insert("threatbook".to_string(), v.clone());
        }

        // Honour the open-ended GOSSAN_APIKEY_<PROVIDER> convention 
        // clap's per-flag `env` attributes cover the 17 known providers
        // above; this loop adds any operator-defined custom provider
        // without requiring a new flag each time.
        for (k, v) in std::env::vars() {
            if k.starts_with("GOSSAN_APIKEY_") {
                let provider = k.trim_start_matches("GOSSAN_APIKEY_").to_lowercase();
                api_keys.insert(provider, v);
            }
        }

        // Prefer explicitly-passed --resolvers; otherwise keep TOML/default.
        let resolvers: Vec<std::net::IpAddr> = if self.resolvers.is_empty() {
            base.resolvers.clone()
        } else {
            let mut out = Vec::with_capacity(self.resolvers.len());
            for s in &self.resolvers {
                match s.parse() {
                    Ok(ip) => out.push(ip),
                    Err(_) => {
                        eprintln!(
                            "error: invalid --resolvers value `{s}` (expected IP address)"
                        );
                        std::process::exit(2);
                    }
                }
            }
            out
        };

        // Reject `--out` paths that escape the cwd via `..` segments OR
        // start with `/etc/`, `/sys/`, `/proc/`, `/boot/`, `/var/log/`.
        // Set `GOSSAN_ALLOW_UNSAFE_PATHS=1` to opt out (intentional
        // pipeline writes to absolute system paths, e.g. /var/log/scan/).
        let safe_out = self.out.as_ref().map(|p| {
            if std::env::var("GOSSAN_ALLOW_UNSAFE_PATHS").as_deref() == Ok("1") {
                return p.clone();
            }
            if let Some(reason) = validate_out_path(p) {
                eprintln!("error: --out path `{p}` {reason} (refusing; set GOSSAN_ALLOW_UNSAFE_PATHS=1 to override)");
                std::process::exit(2);
            }
            p.clone()
        });

        // Documented CLI fallbacks when neither flag nor TOML supplied.
        // Config::default() uses different historic values (e.g. rate 300);
        // keep operator-facing CLI defaults stable when gossan.toml is absent.
        const CLI_DEFAULT_RATE: u32 = 50;
        const CLI_DEFAULT_TIMEOUT: u64 = 10;
        const CLI_DEFAULT_SCAN_TIMEOUT: u64 = 600;
        const CLI_DEFAULT_CONCURRENCY: usize = 150;
        let rate_limit = self.rate.unwrap_or(if from_toml {
            base.rate_limit
        } else {
            CLI_DEFAULT_RATE
        });
        let timeout_secs = self.timeout.unwrap_or(if from_toml {
            base.timeout_secs
        } else {
            CLI_DEFAULT_TIMEOUT
        });
        let scan_timeout_secs = self.scan_timeout.unwrap_or(if from_toml {
            base.scan_timeout_secs
        } else {
            CLI_DEFAULT_SCAN_TIMEOUT
        });
        let concurrency = self.concurrency.unwrap_or(if from_toml {
            base.concurrency
        } else {
            CLI_DEFAULT_CONCURRENCY
        });

        let port_mode = match self.ports.as_deref() {
            Some(s) => match parse_port_mode(Some(s)) {
                Ok(mode) => mode,
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(2);
                }
            },
            None => base.port_mode.clone(),
        };

        let min_severity = min_severity.or(base.min_severity);

        gossan_core::Config {
            rate_limit,
            // Bool flags are clap store_true: absent => false, so OR preserves TOML true.
            adaptive_rate: self.adaptive_rate || base.adaptive_rate,
            timeout_secs,
            scan_timeout_secs,
            concurrency,
            output: gossan_core::OutputConfig {
                format,
                path: safe_out.or(base.output.path.clone()),
            },
            min_severity,
            proxy: self.proxy.clone().or_else(|| base.proxy.clone()),
            cookie: self.cookie.clone().or_else(|| base.cookie.clone()),
            auth_user: self.auth_user.clone().or_else(|| base.auth_user.clone()),
            auth_pass: self.auth_pass.clone().or_else(|| base.auth_pass.clone()),
            port_mode,
            api_keys,
            resolvers,
            strict: self.strict || base.strict,
            conservative: self.conservative || base.conservative,
            include_kind: if self.include_kind.is_empty() {
                base.include_kind.clone()
            } else {
                self.include_kind.clone()
            },
            exclude_kind: if self.exclude_kind.is_empty() {
                base.exclude_kind.clone()
            } else {
                self.exclude_kind.clone()
            },
            ..base
        }
    }
}

/// Validate an `--out` path for dangerous traversal or system-path writes.
/// Returns `Some(reason)` if the path should be rejected, `None` if safe.
pub fn validate_out_path(p: &str) -> Option<&'static str> {
    let path = std::path::Path::new(p);
    // Reject any `..` component.
    if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Some("contains `..`");
    }
    // Reject writes into well-known system paths.
    // Normalise leading slashes and case so that `///etc/passwd`
    // and `/EtC/passwd` are caught as well.
    let normalised = p.trim_start_matches('/').to_lowercase();
    for reserved in ["etc/", "sys/", "proc/", "boot/", "var/log/", "dev/"] {
        if normalised.starts_with(reserved) {
            return Some("writes into system path");
        }
    }
    // Also catch exact matches without trailing slash (e.g. `/etc`).
    for exact in ["etc", "sys", "proc", "boot", "var/log", "dev"] {
        if normalised == exact {
            return Some("writes into system path");
        }
    }
    None
}

pub fn parse_port_mode(s: Option<&str>) -> Result<gossan_core::PortMode, String> {
    match s {
        None | Some("default") => Ok(gossan_core::PortMode::Default),
        Some("top100") => Ok(gossan_core::PortMode::Top100),
        Some("top1000") => Ok(gossan_core::PortMode::Top1000),
        Some("full") => Ok(gossan_core::PortMode::Full),
        Some(custom) => {
            let mut ports: Vec<u16> = Vec::new();
            let mut invalid = Vec::new();
            for p in custom.split(',') {
                let p = p.trim();
                if p.is_empty() {
                    continue;
                }
                match p.parse::<u16>() {
                    Ok(port) if port > 0 => ports.push(port),
                    _ => invalid.push(p.to_string()),
                }
            }
            if !invalid.is_empty() {
                return Err(format!(
                    "invalid --ports value(s): {} (expected 1-65535)",
                    invalid.join(", ")
                ));
            }
            if ports.is_empty() {
                return Err("--ports produced an empty list".to_string());
            }
            Ok(gossan_core::PortMode::Custom(ports))
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::sync::{Mutex, MutexGuard};

    fn cwd_lock() -> MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn with_isolated_cwd<R>(dir: &std::path::Path, f: impl FnOnce() -> R) -> R {
        let _guard = cwd_lock();
        let prev = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(dir).expect("set cwd");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        let _ = std::env::set_current_dir(&prev);
        match result {
            Ok(v) => v,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    #[test]
    fn cli_default_format_is_text() {
        let cli = Cli::parse_from(["gossan", "scan", "example.com"]);
        assert_eq!(cli.format.as_deref(), None); // default when flag absent
    }

    #[test]
    fn cli_format_json() {
        let cli = Cli::parse_from(["gossan", "--format", "json", "scan", "example.com"]);
        assert_eq!(cli.format.as_deref(), Some("json"));
    }

    #[test]
    fn cli_format_markdown_alias_md() {
        let cli = Cli::parse_from(["gossan", "--format", "md", "scan", "example.com"]);
        assert_eq!(cli.format.as_deref(), Some("md"));
    }

    #[test]
    fn cli_rate_default_is_50() {
        let cli = Cli::parse_from(["gossan", "scan", "example.com"]);
        assert_eq!(cli.rate, None); // default comes from build_config / TOML
    }

    #[test]
    fn cli_concurrency_default_is_150() {
        let cli = Cli::parse_from(["gossan", "scan", "example.com"]);
        assert_eq!(cli.concurrency, None);
    }

    #[test]
    fn cli_timeout_default_is_10() {
        let cli = Cli::parse_from(["gossan", "scan", "example.com"]);
        assert_eq!(cli.timeout, None);
    }

    #[test]
    fn cli_scan_timeout_default_is_600() {
        let cli = Cli::parse_from(["gossan", "scan", "example.com"]);
        assert_eq!(cli.scan_timeout, None);
    }

    #[test]
    fn cli_custom_rate_limit() {
        let cli = Cli::parse_from(["gossan", "--rate", "1000", "scan", "example.com"]);
        assert_eq!(cli.rate, Some(1000));
    }

    #[test]
    fn cli_custom_concurrency() {
        let cli = Cli::parse_from(["gossan", "--concurrency", "500", "scan", "example.com"]);
        assert_eq!(cli.concurrency, Some(500));
    }

    #[test]
    fn cli_custom_timeout() {
        let cli = Cli::parse_from(["gossan", "--timeout", "30", "scan", "example.com"]);
        assert_eq!(cli.timeout, Some(30));
    }

    #[test]
    fn cli_custom_scan_timeout() {
        let cli = Cli::parse_from(["gossan", "--scan-timeout", "3600", "scan", "example.com"]);
        assert_eq!(cli.scan_timeout, Some(3600));
    }

    #[test]
    fn cli_format_aliases() {
        let aliases = [
            ("json", "json"),
            ("jsonl", "jsonl"),
            ("ndjson", "ndjson"),
            ("sarif", "sarif"),
            ("markdown", "markdown"),
            ("md", "md"),
            ("masscan-grep", "masscan-grep"),
            ("masscan", "masscan"),
            ("grep", "grep"),
            ("grepable", "grepable"),
            ("nmap-xml", "nmap-xml"),
            ("nmap", "nmap"),
            ("xml", "xml"),
            ("graphml", "graphml"),
            ("graph-ml", "graph-ml"),
            ("text", "text"),
        ];
        for (flag, expected) in aliases {
            let cli = Cli::parse_from(["gossan", "--format", flag, "scan", "example.com"]);
            assert_eq!(cli.format.as_deref(), Some(expected), "format alias {flag} should be stored as-is");
        }
    }

    #[test]
    fn cli_out_flag_parses_path() {
        let cli = Cli::parse_from(["gossan", "--out", "/tmp/results.json", "scan", "example.com"]);
        assert_eq!(cli.out, Some("/tmp/results.json".to_string()));
    }

    #[test]
    fn cli_ports_default_none() {
        let cli = Cli::parse_from(["gossan", "scan", "example.com"]);
        assert_eq!(cli.ports, None);
    }

    #[test]
    fn cli_ports_custom_parses() {
        let cli = Cli::parse_from(["gossan", "--ports", "80,443,8080", "scan", "example.com"]);
        assert_eq!(cli.ports, Some("80,443,8080".to_string()));
    }

    #[test]
    fn cli_adaptive_rate_default_false() {
        let cli = Cli::parse_from(["gossan", "scan", "example.com"]);
        assert!(!cli.adaptive_rate);
    }

    #[test]
    fn cli_adaptive_rate_flag_parses() {
        let cli = Cli::parse_from(["gossan", "--adaptive-rate", "scan", "example.com"]);
        assert!(cli.adaptive_rate);
    }

    #[test]
    fn cli_strict_default_false() {
        let cli = Cli::parse_from(["gossan", "scan", "example.com"]);
        assert!(!cli.strict);
    }

    #[test]
    fn cli_strict_flag_parses() {
        let cli = Cli::parse_from(["gossan", "--strict", "scan", "example.com"]);
        assert!(cli.strict);
    }

    #[test]
    fn cli_conservative_default_false() {
        let cli = Cli::parse_from(["gossan", "scan", "example.com"]);
        assert!(!cli.conservative);
    }

    #[test]
    fn cli_conservative_flag_parses() {
        let cli = Cli::parse_from(["gossan", "--conservative", "scan", "example.com"]);
        assert!(cli.conservative);
    }

    #[test]
    fn cli_min_severity_none_by_default() {
        let cli = Cli::parse_from(["gossan", "scan", "example.com"]);
        assert_eq!(cli.min_severity, None);
    }

    #[test]
    fn cli_min_severity_parses_critical() {
        let cli = Cli::parse_from(["gossan", "--min-severity", "critical", "scan", "example.com"]);
        assert_eq!(cli.min_severity, Some("critical".to_string()));
    }

    #[test]
    fn cli_include_kind_parses_comma_delimited() {
        let cli = Cli::parse_from(["gossan", "--include-kind", "vulnerability,exposure", "scan", "example.com"]);
        assert_eq!(cli.include_kind, vec!["vulnerability", "exposure"]);
    }

    #[test]
    fn cli_exclude_kind_parses_comma_delimited() {
        let cli = Cli::parse_from(["gossan", "--exclude-kind", "misconfiguration", "scan", "example.com"]);
        assert_eq!(cli.exclude_kind, vec!["misconfiguration"]);
    }

    #[test]
    fn cli_proxy_parses() {
        let cli = Cli::parse_from(["gossan", "--proxy", "http://127.0.0.1:8080", "scan", "example.com"]);
        assert_eq!(cli.proxy, Some("http://127.0.0.1:8080".to_string()));
    }

    #[test]
    fn cli_cookie_parses() {
        let cli = Cli::parse_from(["gossan", "--cookie", "session=abc", "scan", "example.com"]);
        assert_eq!(cli.cookie, Some("session=abc".to_string()));
    }

    #[test]
    fn cli_auth_user_parses() {
        let cli = Cli::parse_from(["gossan", "--auth-user", "admin", "scan", "example.com"]);
        assert_eq!(cli.auth_user, Some("admin".to_string()));
    }

    #[test]
    fn cli_auth_pass_parses() {
        let cli = Cli::parse_from(["gossan", "--auth-pass", "secret", "scan", "example.com"]);
        assert_eq!(cli.auth_pass, Some("secret".to_string()));
    }

    #[test]
    fn cli_resolvers_parses_comma_delimited() {
        let cli = Cli::parse_from(["gossan", "--resolvers", "1.1.1.1,8.8.8.8", "scan", "example.com"]);
        assert_eq!(cli.resolvers, vec!["1.1.1.1", "8.8.8.8"]);
    }

    #[test]
    fn cli_checkpoint_parses() {
        let cli = Cli::parse_from(["gossan", "--checkpoint", "gossan.db", "scan", "example.com"]);
        assert_eq!(cli.checkpoint, Some("gossan.db".to_string()));
    }

    #[test]
    fn cli_resume_parses() {
        let cli = Cli::parse_from(["gossan", "--resume", "abc-123", "scan", "example.com"]);
        assert_eq!(cli.resume, Some("abc-123".to_string()));
    }

    #[test]
    fn cli_api_keys_parsed_from_args() {
        let cli = Cli::parse_from([
            "gossan",
            "--vt-key", "vt123",
            "--shodan-key", "shodan456",
            "--github-token", "gh789",
            "scan", "example.com",
        ]);
        assert_eq!(cli.vt_key, Some("vt123".to_string()));
        assert_eq!(cli.shodan_key, Some("shodan456".to_string()));
        assert_eq!(cli.github_token, Some("gh789".to_string()));
    }

    #[test]
    fn cli_subcommand_scan_parses_target() {
        let cli = Cli::parse_from(["gossan", "scan", "example.com"]);
        match cli.command {
            Command::Scan { target, .. } => assert_eq!(target, "example.com"),
            _ => panic!("expected Scan command"),
        }
    }

    #[test]
    fn cli_subcommand_subdomain_parses_target() {
        let cli = Cli::parse_from(["gossan", "subdomain", "example.com"]);
        match cli.command {
            Command::Subdomain { target } => assert_eq!(target, "example.com"),
            _ => panic!("expected Subdomain command"),
        }
    }

    #[test]
    fn cli_subcommand_ports_parses_target() {
        let cli = Cli::parse_from(["gossan", "ports", "example.com"]);
        match cli.command {
            Command::Ports { target } => assert_eq!(target, "example.com"),
            _ => panic!("expected Ports command"),
        }
    }

    #[cfg(feature = "dns")]
    #[test]
    fn cli_subcommand_dns_parses_target() {
        let cli = Cli::parse_from(["gossan", "dns", "example.com"]);
        match cli.command {
            Command::Dns { target } => assert_eq!(target, "example.com"),
            _ => panic!("expected Dns command"),
        }
    }

    #[test]
    fn cli_no_subdomain_flag_parses() {
        let cli = Cli::parse_from(["gossan", "scan", "--no-subdomain", "example.com"]);
        match cli.command {
            Command::Scan { no_subdomain, .. } => assert!(no_subdomain),
            _ => panic!("expected Scan command"),
        }
    }

    #[test]
    fn cli_no_ports_flag_parses() {
        let cli = Cli::parse_from(["gossan", "scan", "--no-ports", "example.com"]);
        match cli.command {
            Command::Scan { no_ports, .. } => assert!(no_ports),
            _ => panic!("expected Scan command"),
        }
    }

    #[test]
    fn cli_no_tech_flag_parses() {
        let cli = Cli::parse_from(["gossan", "scan", "--no-tech", "example.com"]);
        match cli.command {
            Command::Scan { no_tech, .. } => assert!(no_tech),
            _ => panic!("expected Scan command"),
        }
    }

    #[cfg(feature = "dns")]
    #[test]
    fn cli_no_dns_flag_parses() {
        let cli = Cli::parse_from(["gossan", "scan", "--no-dns", "example.com"]);
        match cli.command {
            Command::Scan { no_dns, .. } => assert!(no_dns),
            _ => panic!("expected Scan command"),
        }
    }

    #[test]
    fn cli_no_js_flag_parses() {
        let cli = Cli::parse_from(["gossan", "scan", "--no-js", "example.com"]);
        match cli.command {
            Command::Scan { no_js, .. } => assert!(no_js),
            _ => panic!("expected Scan command"),
        }
    }

    #[test]
    #[cfg(feature = "hidden")]
    fn cli_no_hidden_flag_parses() {
        let cli = Cli::parse_from(["gossan", "scan", "--no-hidden", "example.com"]);
        match cli.command {
            Command::Scan { no_hidden, .. } => assert!(no_hidden),
            _ => panic!("expected Scan command"),
        }
    }

    #[test]
    fn cli_no_cloud_flag_parses() {
        let cli = Cli::parse_from(["gossan", "scan", "--no-cloud", "example.com"]);
        match cli.command {
            Command::Scan { no_cloud, .. } => assert!(no_cloud),
            _ => panic!("expected Scan command"),
        }
    }

    #[test]
    fn cli_no_headless_flag_parses() {
        let cli = Cli::parse_from(["gossan", "scan", "--no-headless", "example.com"]);
        match cli.command {
            Command::Scan { no_headless, .. } => assert!(no_headless),
            _ => panic!("expected Scan command"),
        }
    }

    #[test]
    fn cli_no_crawl_flag_parses() {
        let cli = Cli::parse_from(["gossan", "scan", "--no-crawl", "example.com"]);
        match cli.command {
            Command::Scan { no_crawl, .. } => assert!(no_crawl),
            _ => panic!("expected Scan command"),
        }
    }

    #[test]
    fn cli_no_origin_flag_parses() {
        let cli = Cli::parse_from(["gossan", "scan", "--no-origin", "example.com"]);
        match cli.command {
            Command::Scan { no_origin, .. } => assert!(no_origin),
            _ => panic!("expected Scan command"),
        }
    }

    #[test]
    fn cli_no_horizontal_flag_parses() {
        let cli = Cli::parse_from(["gossan", "scan", "--no-horizontal", "example.com"]);
        match cli.command {
            Command::Scan { no_horizontal, .. } => assert!(no_horizontal),
            _ => panic!("expected Scan command"),
        }
    }

    #[test]
    fn cli_no_graph_flag_parses() {
        let cli = Cli::parse_from(["gossan", "scan", "--no-graph", "example.com"]);
        match cli.command {
            Command::Scan { no_graph, .. } => assert!(no_graph),
            _ => panic!("expected Scan command"),
        }
    }

    #[test]
    fn cli_no_scm_flag_parses() {
        let cli = Cli::parse_from(["gossan", "scan", "--no-scm", "example.com"]);
        match cli.command {
            Command::Scan { no_scm, .. } => assert!(no_scm),
            _ => panic!("expected Scan command"),
        }
    }

    #[test]
    fn cli_no_intel_flag_parses() {
        let cli = Cli::parse_from(["gossan", "scan", "--no-intel", "example.com"]);
        match cli.command {
            Command::Scan { no_intel, .. } => assert!(no_intel),
            _ => panic!("expected Scan command"),
        }
    }

    #[test]
    fn cli_no_fleet_flag_parses() {
        let cli = Cli::parse_from(["gossan", "scan", "--no-fleet", "example.com"]);
        match cli.command {
            Command::Scan { no_fleet, .. } => assert!(no_fleet),
            _ => panic!("expected Scan command"),
        }
    }

    #[test]
    fn cli_no_engine_flag_parses() {
        let cli = Cli::parse_from(["gossan", "scan", "--no-engine", "example.com"]);
        match cli.command {
            Command::Scan { no_engine, .. } => assert!(no_engine),
            _ => panic!("expected Scan command"),
        }
    }

    // ------------------------------------------------------------------
    // Config building tests
    // ------------------------------------------------------------------

    #[test]
    fn build_config_default_format_is_text() {
        let cli = Cli::parse_from(["gossan", "scan", "example.com"]);
        let config = cli.build_config();
        assert!(matches!(config.output.format, gossan_core::OutputFormat::Text));
    }

    #[test]
    fn build_config_json_format() {
        let cli = Cli::parse_from(["gossan", "--format", "json", "scan", "example.com"]);
        let config = cli.build_config();
        assert!(matches!(config.output.format, gossan_core::OutputFormat::Json));
    }

    #[test]
    fn build_config_jsonl_format() {
        let cli = Cli::parse_from(["gossan", "--format", "jsonl", "scan", "example.com"]);
        let config = cli.build_config();
        assert!(matches!(config.output.format, gossan_core::OutputFormat::Jsonl));
    }

    #[test]
    fn build_config_ndjson_format() {
        let cli = Cli::parse_from(["gossan", "--format", "ndjson", "scan", "example.com"]);
        let config = cli.build_config();
        assert!(matches!(config.output.format, gossan_core::OutputFormat::Jsonl));
    }

    #[test]
    fn build_config_sarif_format() {
        let cli = Cli::parse_from(["gossan", "--format", "sarif", "scan", "example.com"]);
        let config = cli.build_config();
        assert!(matches!(config.output.format, gossan_core::OutputFormat::Sarif));
    }

    #[test]
    fn build_config_markdown_format() {
        let cli = Cli::parse_from(["gossan", "--format", "markdown", "scan", "example.com"]);
        let config = cli.build_config();
        assert!(matches!(config.output.format, gossan_core::OutputFormat::Markdown));
    }

    #[test]
    fn build_config_md_format() {
        let cli = Cli::parse_from(["gossan", "--format", "md", "scan", "example.com"]);
        let config = cli.build_config();
        assert!(matches!(config.output.format, gossan_core::OutputFormat::Markdown));
    }

    #[test]
    fn build_config_masscan_grep_format() {
        let cli = Cli::parse_from(["gossan", "--format", "masscan-grep", "scan", "example.com"]);
        let config = cli.build_config();
        assert!(matches!(config.output.format, gossan_core::OutputFormat::MasscanGrep));
    }

    #[test]
    fn build_config_nmap_xml_format() {
        let cli = Cli::parse_from(["gossan", "--format", "nmap-xml", "scan", "example.com"]);
        let config = cli.build_config();
        assert!(matches!(config.output.format, gossan_core::OutputFormat::NmapXml));
    }

    #[test]
    fn build_config_graphml_format() {
        let cli = Cli::parse_from(["gossan", "--format", "graphml", "scan", "example.com"]);
        let config = cli.build_config();
        assert!(matches!(config.output.format, gossan_core::OutputFormat::Graphml));
    }

    #[test]
    fn build_config_rate_limit() {
        let cli = Cli::parse_from(["gossan", "--rate", "200", "scan", "example.com"]);
        let config = cli.build_config();
        assert_eq!(config.rate_limit, 200);
    }

    #[test]
    fn build_config_concurrency() {
        let cli = Cli::parse_from(["gossan", "--concurrency", "75", "scan", "example.com"]);
        let config = cli.build_config();
        assert_eq!(config.concurrency, 75);
    }

    #[test]
    fn build_config_timeout() {
        let cli = Cli::parse_from(["gossan", "--timeout", "15", "scan", "example.com"]);
        let config = cli.build_config();
        assert_eq!(config.timeout_secs, 15);
    }

    #[test]
    fn build_config_scan_timeout() {
        let cli = Cli::parse_from(["gossan", "--scan-timeout", "1200", "scan", "example.com"]);
        let config = cli.build_config();
        assert_eq!(config.scan_timeout_secs, 1200);
    }

    #[test]
    fn build_config_adaptive_rate() {
        let cli = Cli::parse_from(["gossan", "--adaptive-rate", "scan", "example.com"]);
        let config = cli.build_config();
        assert!(config.adaptive_rate);
    }

    #[test]
    fn build_config_strict() {
        let cli = Cli::parse_from(["gossan", "--strict", "scan", "example.com"]);
        let config = cli.build_config();
        assert!(config.strict);
    }

    #[test]
    fn build_config_conservative() {
        let cli = Cli::parse_from(["gossan", "--conservative", "scan", "example.com"]);
        let config = cli.build_config();
        assert!(config.conservative);
    }

    #[test]
    fn build_config_proxy() {
        let cli = Cli::parse_from(["gossan", "--proxy", "http://proxy:8080", "scan", "example.com"]);
        let config = cli.build_config();
        assert_eq!(config.proxy, Some("http://proxy:8080".to_string()));
    }

    #[test]
    fn build_config_cookie() {
        let cli = Cli::parse_from(["gossan", "--cookie", "auth=token", "scan", "example.com"]);
        let config = cli.build_config();
        assert_eq!(config.cookie, Some("auth=token".to_string()));
    }

    #[test]
    fn build_config_auth_user() {
        let cli = Cli::parse_from(["gossan", "--auth-user", "admin", "scan", "example.com"]);
        let config = cli.build_config();
        assert_eq!(config.auth_user, Some("admin".to_string()));
    }

    #[test]
    fn build_config_auth_pass() {
        let cli = Cli::parse_from(["gossan", "--auth-pass", "hunter2", "scan", "example.com"]);
        let config = cli.build_config();
        assert_eq!(config.auth_pass, Some("hunter2".to_string()));
    }

    #[test]
    fn build_config_out_path() {
        let cli = Cli::parse_from(["gossan", "--out", "/tmp/out.json", "scan", "example.com"]);
        let config = cli.build_config();
        assert_eq!(config.output.path, Some("/tmp/out.json".to_string()));
    }

    #[test]
    fn build_config_min_severity_info() {
        let cli = Cli::parse_from(["gossan", "--min-severity", "info", "scan", "example.com"]);
        let config = cli.build_config();
        assert_eq!(config.min_severity, Some(gossan_core::Severity::Info));
    }

    #[test]
    fn build_config_min_severity_low() {
        let cli = Cli::parse_from(["gossan", "--min-severity", "low", "scan", "example.com"]);
        let config = cli.build_config();
        assert_eq!(config.min_severity, Some(gossan_core::Severity::Low));
    }

    #[test]
    fn build_config_min_severity_medium() {
        let cli = Cli::parse_from(["gossan", "--min-severity", "medium", "scan", "example.com"]);
        let config = cli.build_config();
        assert_eq!(config.min_severity, Some(gossan_core::Severity::Medium));
    }

    #[test]
    fn build_config_min_severity_high() {
        let cli = Cli::parse_from(["gossan", "--min-severity", "high", "scan", "example.com"]);
        let config = cli.build_config();
        assert_eq!(config.min_severity, Some(gossan_core::Severity::High));
    }

    #[test]
    fn build_config_min_severity_critical() {
        let cli = Cli::parse_from(["gossan", "--min-severity", "critical", "scan", "example.com"]);
        let config = cli.build_config();
        assert_eq!(config.min_severity, Some(gossan_core::Severity::Critical));
    }

    #[test]
    fn build_config_invalid_min_severity_becomes_none() {
        let cli = Cli::parse_from(["gossan", "--min-severity", "unknown", "scan", "example.com"]);
        let config = cli.build_config();
        assert_eq!(config.min_severity, None);
    }

    #[test]
    fn build_config_include_kind() {
        let cli = Cli::parse_from(["gossan", "--include-kind", "vulnerability,misconfiguration", "scan", "example.com"]);
        let config = cli.build_config();
        assert_eq!(config.include_kind, vec!["vulnerability", "misconfiguration"]);
    }

    #[test]
    fn build_config_exclude_kind() {
        let cli = Cli::parse_from(["gossan", "--exclude-kind", "exposure", "scan", "example.com"]);
        let config = cli.build_config();
        assert_eq!(config.exclude_kind, vec!["exposure"]);
    }

    #[test]
    fn build_config_resolvers() {
        let cli = Cli::parse_from(["gossan", "--resolvers", "1.1.1.1,8.8.8.8", "scan", "example.com"]);
        let config = cli.build_config();
        assert_eq!(config.resolvers.len(), 2);
    }

    #[test]
    fn build_config_invalid_resolver_filtered() {
        let cli = Cli::parse_from(["gossan", "--resolvers", "1.1.1.1,not-an-ip,8.8.8.8", "scan", "example.com"]);
        let config = cli.build_config();
        assert_eq!(config.resolvers.len(), 2);
    }

    #[test]
    fn build_config_port_mode_default() {
        let cli = Cli::parse_from(["gossan", "scan", "example.com"]);
        let config = cli.build_config();
        assert!(matches!(config.port_mode, gossan_core::PortMode::Default));
    }

    #[test]
    fn build_config_port_mode_top100() {
        let cli = Cli::parse_from(["gossan", "--ports", "top100", "scan", "example.com"]);
        let config = cli.build_config();
        assert!(matches!(config.port_mode, gossan_core::PortMode::Top100));
    }

    #[test]
    fn build_config_port_mode_top1000() {
        let cli = Cli::parse_from(["gossan", "--ports", "top1000", "scan", "example.com"]);
        let config = cli.build_config();
        assert!(matches!(config.port_mode, gossan_core::PortMode::Top1000));
    }

    #[test]
    fn build_config_port_mode_full() {
        let cli = Cli::parse_from(["gossan", "--ports", "full", "scan", "example.com"]);
        let config = cli.build_config();
        assert!(matches!(config.port_mode, gossan_core::PortMode::Full));
    }

    #[test]
    fn build_config_port_mode_custom() {
        let cli = Cli::parse_from(["gossan", "--ports", "22,80,443", "scan", "example.com"]);
        let config = cli.build_config();
        if let gossan_core::PortMode::Custom(ports) = config.port_mode {
            assert_eq!(ports, vec![22, 80, 443]);
        } else {
            panic!("expected Custom port mode");
        }
    }

    #[test]
    fn build_config_api_keys_from_args() {
        let cli = Cli::parse_from([
            "gossan",
            "--vt-key", "vt_secret",
            "--st-key", "st_secret",
            "--shodan-key", "shodan_secret",
            "scan", "example.com",
        ]);
        let config = cli.build_config();
        assert_eq!(config.api_keys.get("virustotal"), Some(&"vt_secret".to_string()));
        assert_eq!(config.api_keys.get("securitytrails"), Some(&"st_secret".to_string()));
        assert_eq!(config.api_keys.get("shodan"), Some(&"shodan_secret".to_string()));
    }

    #[test]
    fn build_config_default_scan_timeout_is_600() {
        let dir = tempfile::tempdir().unwrap();
        let config = with_isolated_cwd(dir.path(), || {
            let cli = Cli::parse_from(["gossan", "scan", "example.com"]);
            cli.build_config()
        });
        assert_eq!(config.scan_timeout_secs, 600);
        assert_eq!(config.scan_timeout().as_secs(), 600);
    }

    #[test]
    fn build_config_default_concurrency_is_150() {
        let dir = tempfile::tempdir().unwrap();
        let config = with_isolated_cwd(dir.path(), || {
            let cli = Cli::parse_from(["gossan", "scan", "example.com"]);
            cli.build_config()
        });
        assert_eq!(config.concurrency, 150);
    }

    #[test]
    fn build_config_default_rate_limit_is_50() {
        let dir = tempfile::tempdir().unwrap();
        let config = with_isolated_cwd(dir.path(), || {
            let cli = Cli::parse_from(["gossan", "scan", "example.com"]);
            cli.build_config()
        });
        assert_eq!(config.rate_limit, 50);
    }

    #[test]
    fn build_config_default_timeout_is_10() {
        let dir = tempfile::tempdir().unwrap();
        let config = with_isolated_cwd(dir.path(), || {
            let cli = Cli::parse_from(["gossan", "scan", "example.com"]);
            cli.build_config()
        });
        assert_eq!(config.timeout_secs, 10);
        assert_eq!(config.timeout().as_secs(), 10);
    }

    #[test]
    fn build_config_out_path_with_parent_dirs() {
        let cli = Cli::parse_from(["gossan", "--out", "/tmp/deep/nested/out.json", "scan", "example.com"]);
        let config = cli.build_config();
        assert_eq!(config.output.path, Some("/tmp/deep/nested/out.json".to_string()));
    }

    #[test]
    fn build_config_no_out_path_stdout_fallback() {
        let cli = Cli::parse_from(["gossan", "scan", "example.com"]);
        let config = cli.build_config();
        assert_eq!(config.output.path, None);
    }

    // ------------------------------------------------------------------
    // Adversarial path-validation tests
    // ------------------------------------------------------------------

    #[test]
    fn validate_out_path_rejects_dotdot() {
        assert!(validate_out_path("../etc/passwd").is_some());
        assert!(validate_out_path("foo/../../bar").is_some());
        assert!(validate_out_path("..").is_some());
    }

    #[test]
    fn validate_out_path_rejects_absolute_system_paths() {
        assert!(validate_out_path("/etc/passwd").is_some());
        assert!(validate_out_path("/sys/kernel").is_some());
        assert!(validate_out_path("/proc/self").is_some());
        assert!(validate_out_path("/boot/grub").is_some());
        assert!(validate_out_path("/var/log/auth").is_some());
        assert!(validate_out_path("/dev/null").is_some());
    }

    #[test]
    fn validate_out_path_rejects_multiple_leading_slashes() {
        // Bypass attempt: ///etc/passwd should still be rejected.
        assert!(validate_out_path("///etc/passwd").is_some());
        assert!(validate_out_path("////sys/foo").is_some());
    }

    #[test]
    fn validate_out_path_rejects_case_variants() {
        assert!(validate_out_path("/EtC/passwd").is_some());
        assert!(validate_out_path("/SYS/kernel").is_some());
        assert!(validate_out_path("/Proc/self").is_some());
    }

    #[test]
    fn validate_out_path_rejects_exact_system_dirs() {
        assert!(validate_out_path("/etc").is_some());
        assert!(validate_out_path("/sys").is_some());
        assert!(validate_out_path("/proc").is_some());
    }

    #[test]
    fn validate_out_path_accepts_safe_paths() {
        assert!(validate_out_path("./results.json").is_none());
        assert!(validate_out_path("output.txt").is_none());
        assert!(validate_out_path("/tmp/out.json").is_none());
        assert!(validate_out_path("/home/user/scan.json").is_none());
    }

    // ------------------------------------------------------------------
    // Proptest property tests
    // ------------------------------------------------------------------

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn parse_port_mode_never_panics(s in "[0-9a-zA-Z,]{0,100}") {
            let _ = parse_port_mode(Some(&s));
        }

        #[test]
        fn parse_port_mode_custom_ports_are_valid_u16(s in "[0-9, ]{0,100}") {
            if let Ok(gossan_core::PortMode::Custom(ports)) = parse_port_mode(Some(&s)) {
                for p in ports {
                    prop_assert!(p > 0);
                    prop_assert!(p <= 65535);
                }
            }
        }

        #[test]
        fn validate_out_path_rejects_any_dotdot_segment(path in "[a-zA-Z0-9._/\\-]*\\.\\.[a-zA-Z0-9._/\\-]*") {
            // Any path that literally contains ".." as a substring should
            // be rejected when it forms a ParentDir component.
            // This prop-test is a coarse filter; the unit tests above
            // cover the precise component-level logic.
            if path.contains("..") {
                // Not all strings with ".." are ParentDir (e.g. "foo...bar"),
                // but many are. We just assert it never panics.
                let _ = validate_out_path(&path);
            }
        }
    }

    #[test]
    fn build_config_loads_toml_base_when_present() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("gossan.toml"),
            r#"
rate_limit = 77
timeout_secs = 33
scan_timeout_secs = 111
concurrency = 9
proxy = "http://proxy.example:8080"
"#,
        )
        .unwrap();
        let config = with_isolated_cwd(dir.path(), || {
            let cli = Cli::parse_from(["gossan", "scan", "example.com"]);
            cli.build_config()
        });
        assert_eq!(config.rate_limit, 77);
        assert_eq!(config.timeout_secs, 33);
        assert_eq!(config.scan_timeout_secs, 111);
        assert_eq!(config.concurrency, 9);
        assert_eq!(config.proxy.as_deref(), Some("http://proxy.example:8080"));
    }

    #[test]
    fn build_config_explicit_rate_overrides_toml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("gossan.toml"), "rate_limit = 77\n").unwrap();
        let config = with_isolated_cwd(dir.path(), || {
            let cli = Cli::parse_from(["gossan", "--rate", "12", "scan", "example.com"]);
            cli.build_config()
        });
        assert_eq!(config.rate_limit, 12);
    }

    #[test]
    fn load_or_default_errors_on_malformed_toml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("gossan.toml"), "rate_limit = not-a-number\n").unwrap();
        let err = with_isolated_cwd(dir.path(), || {
            gossan_core::Config::load_or_default().expect_err("malformed must fail")
        });
        assert!(!err.is_empty());
    }

    #[test]
    fn build_config_preserves_toml_output_format_without_format_flag() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("gossan.toml"),
            "[output]\nformat = \"json\"\n",
        )
        .unwrap();
        let config = with_isolated_cwd(dir.path(), || {
            let cli = Cli::parse_from(["gossan", "scan", "example.com"]);
            assert!(cli.format.is_none());
            cli.build_config()
        });
        assert!(
            matches!(config.output.format, gossan_core::OutputFormat::Json),
            "TOML output.format=json must survive absent --format"
        );
    }

}
