//! Scanner configuration — rate limits, proxy, modules, API keys, output.
//!
//! [`Config`] is the single source of truth for all scanner behaviour.
//! CLI flags merge into it via struct update syntax.

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::Severity;

/// API keys for optional paid/rate-limited discovery sources.
/// All fields also read from environment variables or `gossan.toml`.
pub type ApiKeys = std::collections::HashMap<String, String>;

/// Which ports to scan. Determined at scan startup and passed through `Config`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PortMode {
    /// Built-in list of 52 high-risk service ports.
    #[default]
    Default,
    /// nmap's top-100 ports by scan frequency.
    Top100,
    /// nmap's top-1000 ports by scan frequency.
    Top1000,
    /// Full range 1–65535.
    Full,
    /// Explicit comma-separated list supplied by the user.
    Custom(Vec<u16>),
}

/// Crawl scanner configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlConfig {
    /// Maximum pages to crawl per web asset.
    pub max_pages: usize,
    /// Maximum crawl depth (clicks from seed page).
    pub max_depth: usize,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            max_pages: 50,
            max_depth: 3,
        }
    }
}

/// Global scan configuration — timeouts, concurrency, resolvers, and module toggles.
///
/// Load from `gossan.toml` via [`Config::load_or_default`] or construct programmatically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Global requests-per-second cap across all scanners. When
    /// `adaptive_rate` is enabled this becomes the *ceiling*; the
    /// engine starts at half-rate and ramps based on observed loss.
    pub rate_limit: u32,
    /// Enable closed-loop AIMD rate control in `gossan-engine`. Halves
    /// the enforced rate on TX-drop bursts and additively recovers
    /// after streaks of clean batches. No-op for non-engine scanners.
    #[serde(default)]
    pub adaptive_rate: bool,
    /// Per-request timeout in seconds.
    pub timeout_secs: u64,
    /// Max concurrent tasks per scanner.
    pub concurrency: usize,
    /// DNS resolvers (defaults to Cloudflare + Google).
    pub resolvers: Vec<IpAddr>,
    /// HTTP User-Agent header.
    pub user_agent: String,
    /// Optional HTTP proxy for all outbound requests.
    pub proxy: Option<String>,
    /// Accept invalid HTTPS certificates. Disabled by default.
    #[serde(default)]
    pub insecure_tls: bool,
    /// Optional Cookie header for authenticated crawling.
    pub cookie: Option<String>,
    /// Optional username for authenticated crawling.
    pub auth_user: Option<String>,
    /// Optional password for authenticated crawling.
    pub auth_pass: Option<String>,
    /// Per-module enablement flags keyed by scanner module name.
    #[serde(default)]
    pub modules: std::collections::HashMap<String, bool>,
    /// Output destination and serialization settings.
    pub output: OutputConfig,
    /// Suppress findings below this severity. None = show all.
    pub min_severity: Option<Severity>,
    /// Port scanning mode.
    pub port_mode: PortMode,
    /// Path to the local Passive Intel SQLite database.
    pub intel_db_path: Option<String>,
    /// Optional API keys for paid/key-gated data sources.
    #[serde(default)]
    pub api_keys: ApiKeys,
    /// Crawl scanner settings.
    #[serde(default)]
    pub crawl: CrawlConfig,
    /// Per-host delay between requests in milliseconds (default: 100).
    /// Set to 0 to disable per-host rate limiting.
    #[serde(default = "default_host_delay_ms")]
    pub host_delay_ms: u64,
    /// Max response body size in bytes (e.g. 10MB).
    #[serde(default = "default_max_response_size")]
    pub max_response_size: usize,
    /// Abort the entire pipeline on any scanner error (for debugging).
    #[serde(default)]
    pub strict: bool,
    /// Conservative mode for zero-false-positive horizontal scanning.
    #[serde(default)]
    pub conservative: bool,
    /// Only include findings matching these kinds. Empty = all kinds.
    #[serde(default)]
    pub include_kind: Vec<String>,
    /// Exclude findings matching these kinds.
    #[serde(default)]
    pub exclude_kind: Vec<String>,
}

fn default_max_response_size() -> usize {
    10 * 1024 * 1024 // 10MB
}

fn default_host_delay_ms() -> u64 {
    100
}

impl Config {
    /// Per-request timeout as a [`Duration`].
    #[must_use]
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }

    /// Load configuration from a TOML file, merging on top of defaults.
    ///
    /// Fields present in the file override the default; absent fields keep
    /// the default value. CLI flags should override the result of this.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or contains invalid TOML.
    pub fn from_toml(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config {}: {e}", path.display()))?;
        toml::from_str(&content)
            .map_err(|e| format!("failed to parse config {}: {e}", path.display()))
    }

    /// Try loading `gossan.toml` from the current directory.
    /// Returns `Config::default()` if the file does not exist.
    ///
    /// # Errors
    ///
    /// Returns an error only if the file exists but is malformed.
    pub fn load_or_default() -> Result<Self, String> {
        let path = Path::new("gossan.toml");
        if path.exists() {
            Self::from_toml(path)
        } else {
            Ok(Self::default())
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rate_limit: 300,
            adaptive_rate: false,
            timeout_secs: 10,
            concurrency: 200,
            resolvers: vec![
                IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            ],
            user_agent: concat!(
                "gossan/",
                env!("CARGO_PKG_VERSION"),
                " (+https://github.com/santht/gossan)"
            )
            .to_string(),
            proxy: None,
            insecure_tls: false,
            cookie: None,
            auth_user: None,
            auth_pass: None,
            modules: std::collections::HashMap::new(),
            output: OutputConfig::default(),
            min_severity: None,
            port_mode: PortMode::Default,
            intel_db_path: None,
            api_keys: ApiKeys::default(),
            crawl: CrawlConfig::default(),
            host_delay_ms: default_host_delay_ms(),
            max_response_size: default_max_response_size(),
            strict: false,
            conservative: false,
            include_kind: Vec::new(),
            exclude_kind: Vec::new(),
        }
    }
}

/// Per-module enablement flags keyed by scanner module name.
pub type ModuleConfig = std::collections::HashMap<String, bool>;
/// Output format for scan results.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// Pretty-printed JSON object.
    Json,
    /// Newline-delimited JSON (one finding per line).
    Jsonl,
    /// SARIF v2.1 (compatible with GitHub Advanced Security).
    Sarif,
    /// Human-readable terminal output.
    Text,
    /// Markdown report.
    Markdown,
    /// Masscan-grepable (`-oG` style):
    /// `Host: <ip> ()\tPorts: <port>/open/<proto>//<service>//`
    /// Lines are emitted only for findings that carry an
    /// `Evidence::Banner` payload tagged `port:N` — i.e. open ports
    /// discovered by `gossan-portscan` / `gossan-engine`.
    MasscanGrep,
    /// nmap-compatible XML (`-oX` style). Subset that covers the
    /// shape downstream parsers rely on: `<nmaprun>` root with one
    /// `<host>` element per discovered IP and one `<port>` child per
    /// open port. State is hard-coded `open`.
    NmapXml,
    /// GraphML (XML-based graph format) for export to Gephi /
    /// Cytoscape / yEd. Nodes are findings keyed by target; edges
    /// link findings that share a target.
    Graphml,
}

/// Where and how to write scan output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Output format.
    pub format: OutputFormat,
    /// Optional file path (writes to stdout if `None`).
    pub path: Option<String>,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Text,
            path: None,
        }
    }
}
