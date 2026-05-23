//! CLI argument definitions — clap-derived command tree.

use clap::{Parser, Subcommand};
#[derive(Parser)]
#[command(
    name    = "gossan",
    version,
    about   = "Attack surface discovery — subdomains, ports, tech stack, JS secrets, hidden endpoints, cloud assets",
    long_about = None,
)]
/// Top-level CLI argument parser for the gossan binary.
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    // ── Output ─────────────────────────────────────────────────────────────
    #[arg(
        long,
        default_value = "text",
        global = true,
        help = "Output format: text | json | jsonl | sarif | markdown | masscan-grep | nmap-xml | graphml"
    )]
    pub format: String,
    #[arg(long, global = true, help = "Write output to file instead of stdout")]
    pub out: Option<String>,

    // ── Tuning ─────────────────────────────────────────────────────────────
    #[arg(
        long,
        default_value = "300",
        global = true,
        help = "Max requests per second (also the AIMD ceiling when --adaptive-rate is set)"
    )]
    pub rate: u32,
    #[arg(
        long,
        global = true,
        help = "Enable closed-loop AIMD rate adaptation in `gossan engine` (halves on TX-drop bursts; ramps after clean batches)"
    )]
    pub adaptive_rate: bool,
    #[arg(
        long,
        default_value = "10",
        global = true,
        help = "Per-request timeout in seconds"
    )]
    pub timeout: u64,
    #[arg(
        long,
        default_value = "150",
        global = true,
        help = "Max concurrent tasks"
    )]
    pub concurrency: usize,
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
    /// Full scan — all compiled-in modules in pipeline order
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

    // Individual module subcommands — only compiled in when the feature is active
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
    /// Authenticated web crawling — form extraction, parameter discovery
    Crawl { target: String },

    #[cfg(feature = "origin")]
    /// Origin IP discovery — find true server IPs behind CDNs/WAFs
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
        let format = match self.format.as_str() {
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
        };

        let min_severity = self.min_severity.as_deref().and_then(|s| match s {
            "info" => Some(gossan_core::Severity::Info),
            "low" => Some(gossan_core::Severity::Low),
            "medium" => Some(gossan_core::Severity::Medium),
            "high" => Some(gossan_core::Severity::High),
            "critical" => Some(gossan_core::Severity::Critical),
            _ => None,
        });

        let port_mode = parse_port_mode(self.ports.as_deref());

        let mut api_keys = std::collections::HashMap::new();
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

        for (k, v) in std::env::vars() {
            if k.starts_with("GOSSAN_APIKEY_") {
                let provider = k.trim_start_matches("GOSSAN_APIKEY_").to_lowercase();
                api_keys.insert(provider, v);
            }
        }
        if let Ok(v) = std::env::var("VT_API_KEY") {
            api_keys.insert("virustotal".to_string(), v);
        }
        if let Ok(v) = std::env::var("ST_API_KEY") {
            api_keys.insert("securitytrails".to_string(), v);
        }
        if let Ok(v) = std::env::var("SHODAN_API_KEY") {
            api_keys.insert("shodan".to_string(), v);
        }
        if let Ok(v) = std::env::var("GITHUB_TOKEN") {
            api_keys.insert("github".to_string(), v);
        }
        if let Ok(v) = std::env::var("CENSYS_API_KEY") {
            api_keys.insert("censys".to_string(), v);
        }
        if let Ok(v) = std::env::var("BINARYEDGE_API_KEY") {
            api_keys.insert("binaryedge".to_string(), v);
        }
        if let Ok(v) = std::env::var("FULLHUNT_API_KEY") {
            api_keys.insert("fullhunt".to_string(), v);
        }
        if let Ok(v) = std::env::var("CHAOS_API_KEY") {
            api_keys.insert("chaos".to_string(), v);
        }
        if let Ok(v) = std::env::var("BEVIGIL_API_KEY") {
            api_keys.insert("bevigil".to_string(), v);
        }
        if let Ok(v) = std::env::var("FOFA_API_KEY") {
            api_keys.insert("fofa".to_string(), v);
        }
        if let Ok(v) = std::env::var("HUNTER_API_KEY") {
            api_keys.insert("hunter".to_string(), v);
        }
        if let Ok(v) = std::env::var("NETLAS_API_KEY") {
            api_keys.insert("netlas".to_string(), v);
        }
        if let Ok(v) = std::env::var("ZOOMEYE_API_KEY") {
            api_keys.insert("zoomeye".to_string(), v);
        }
        if let Ok(v) = std::env::var("C99_API_KEY") {
            api_keys.insert("c99".to_string(), v);
        }
        if let Ok(v) = std::env::var("QUAKE_API_KEY") {
            api_keys.insert("quake".to_string(), v);
        }
        if let Ok(v) = std::env::var("THREATBOOK_API_KEY") {
            api_keys.insert("threatbook".to_string(), v);
        }

        let resolvers: Vec<std::net::IpAddr> = self
            .resolvers
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        // Reject `--out` paths that escape the cwd via `..` segments OR
        // start with `/etc/`, `/sys/`, `/proc/`, `/boot/`, `/var/log/`.
        // Set `GOSSAN_ALLOW_UNSAFE_PATHS=1` to opt out (intentional
        // pipeline writes to absolute system paths, e.g. /var/log/scan/).
        let safe_out = self.out.as_ref().map(|p| {
            if std::env::var("GOSSAN_ALLOW_UNSAFE_PATHS").as_deref() == Ok("1") {
                return p.clone();
            }
            let path = std::path::Path::new(p);
            // Reject any `..` component.
            if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
                eprintln!("error: --out path `{p}` contains `..` (refusing to write outside cwd; set GOSSAN_ALLOW_UNSAFE_PATHS=1 to override)");
                std::process::exit(2);
            }
            // Reject writes into well-known system paths.
            for reserved in ["/etc/", "/sys/", "/proc/", "/boot/", "/var/log/", "/dev/"] {
                if p.starts_with(reserved) {
                    eprintln!("error: --out path `{p}` writes into system path `{reserved}` (refusing; set GOSSAN_ALLOW_UNSAFE_PATHS=1 to override)");
                    std::process::exit(2);
                }
            }
            p.clone()
        });

        gossan_core::Config {
            rate_limit: self.rate,
            adaptive_rate: self.adaptive_rate,
            timeout_secs: self.timeout,
            concurrency: self.concurrency,
            output: gossan_core::OutputConfig {
                format,
                path: safe_out,
            },
            min_severity,
            proxy: self.proxy.clone(),
            cookie: self.cookie.clone(),
            auth_user: self.auth_user.clone(),
            auth_pass: self.auth_pass.clone(),
            port_mode,
            api_keys,
            resolvers,
            strict: self.strict,
            conservative: self.conservative,
            include_kind: self.include_kind.clone(),
            exclude_kind: self.exclude_kind.clone(),
            ..gossan_core::Config::default()
        }
    }
}

pub fn parse_port_mode(s: Option<&str>) -> gossan_core::PortMode {
    match s {
        None | Some("default") => gossan_core::PortMode::Default,
        Some("top100") => gossan_core::PortMode::Top100,
        Some("top1000") => gossan_core::PortMode::Top1000,
        Some("full") => gossan_core::PortMode::Full,
        Some(custom) => {
            let ports: Vec<u16> = custom
                .split(',')
                .filter_map(|p| p.trim().parse::<u16>().ok())
                .collect();
            if ports.is_empty() {
                gossan_core::PortMode::Default
            } else {
                gossan_core::PortMode::Custom(ports)
            }
        }
    }
}
