use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::Severity;

/// API keys for optional paid/rate-limited subdomain sources.
/// All fields also read from environment variables (takes precedence over struct values).
#[allow(clippy::doc_markdown)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApiKeys {
    /// VirusTotal — `$VT_API_KEY`. Free tier: 500 req/day, 4 req/min.
    pub virustotal: Option<String>,
    /// SecurityTrails — `$ST_API_KEY`.
    pub securitytrails: Option<String>,
    /// Shodan — `$SHODAN_API_KEY`.
    pub shodan: Option<String>,
    /// GitHub personal access token — `$GITHUB_TOKEN`. Used for code-search subdomain discovery.
    pub github: Option<String>,
}

impl ApiKeys {
    /// Load API keys from environment variables, overriding any struct values.
    #[must_use]
    pub fn resolve(mut self) -> Self {
        if let Ok(v) = std::env::var("VT_API_KEY") {
            self.virustotal = Some(v);
        }
        if let Ok(v) = std::env::var("ST_API_KEY") {
            self.securitytrails = Some(v);
        }
        if let Ok(v) = std::env::var("SHODAN_API_KEY") {
            self.shodan = Some(v);
        }
        if let Ok(v) = std::env::var("GITHUB_TOKEN") {
            self.github = Some(v);
        }
        self
    }
}

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
    /// Global requests-per-second cap across all scanners.
    pub rate_limit: u32,
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
    pub modules: ModuleConfig,
    pub output: OutputConfig,
    /// Suppress findings below this severity. None = show all.
    pub min_severity: Option<Severity>,
    /// Port scanning mode.
    pub port_mode: PortMode,
    /// Optional API keys for paid/key-gated data sources.
    pub api_keys: ApiKeys,
    /// Crawl scanner settings.
    #[serde(default)]
    pub crawl: CrawlConfig,
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
            timeout_secs: 10,
            concurrency: 200,
            resolvers: vec![
                IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            ],
            user_agent: concat!(
                "gossan/",
                env!("CARGO_PKG_VERSION"),
                " (+https://github.com/santhsecurity/gossan)"
            )
            .to_string(),
            proxy: None,
            insecure_tls: false,
            cookie: None,
            modules: ModuleConfig::default(),
            output: OutputConfig::default(),
            min_severity: None,
            port_mode: PortMode::Default,
            api_keys: ApiKeys::default(),
            crawl: CrawlConfig::default(),
        }
    }
}

/// Which scanner modules are enabled for this run.
///
/// Each field corresponds to a scanner crate. Use [`ModuleConfig::all`] to
/// enable everything.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModuleConfig {
    /// Subdomain enumeration (passive + brute-force).
    pub subdomain: bool,
    /// TCP connect port scanning.
    pub portscan: bool,
    /// Technology fingerprinting (via truestack).
    pub techstack: bool,
    /// DNS security auditing (SPF, DMARC, DKIM, AXFR, takeover).
    pub dns: bool,
    /// JavaScript analysis (secrets, endpoints, prototype pollution).
    pub js: bool,
    /// Hidden endpoint discovery (CORS, SSRF, Swagger, cache deception).
    pub hidden: bool,
    /// Cloud storage bucket discovery (S3, GCS, Azure, DO Spaces).
    pub cloud: bool,
    /// Raw SYN port scanning (requires root/`CAP_NET_RAW`).
    pub synscan: bool,
    /// Headless browser rendering and XHR trapping.
    pub headless: bool,
    /// Authenticated web crawling (form + parameter discovery).
    pub crawl: bool,
}

impl ModuleConfig {
    /// Returns a config with every scanner module enabled.
    #[must_use]
    pub fn all() -> Self {
        Self {
            subdomain: true,
            portscan: true,
            techstack: true,
            dns: true,
            js: true,
            hidden: true,
            cloud: true,
            synscan: true,
            headless: true,
            crawl: true,
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn config_default_timeout_matches_timeout_secs() {
        let config = Config::default();
        assert_eq!(config.timeout(), Duration::from_secs(config.timeout_secs));
    }

    #[test]
    fn module_config_all_enables_every_module() {
        let modules = ModuleConfig::all();
        assert!(modules.subdomain);
        assert!(modules.portscan);
        assert!(modules.techstack);
        assert!(modules.dns);
        assert!(modules.js);
        assert!(modules.hidden);
        assert!(modules.cloud);
        assert!(modules.synscan);
        assert!(modules.headless);
        assert!(modules.crawl);
    }

    #[test]
    fn output_config_defaults_to_text_and_no_path() {
        let output = OutputConfig::default();
        assert!(matches!(output.format, OutputFormat::Text));
        assert_eq!(output.path, None);
    }

    #[test]
    fn port_mode_serializes_snake_case_variants() {
        assert_eq!(
            serde_json::to_value(PortMode::Default).unwrap(),
            json!("default")
        );
        assert_eq!(
            serde_json::to_value(PortMode::Top100).unwrap(),
            json!("top100")
        );
        assert_eq!(
            serde_json::to_value(PortMode::Top1000).unwrap(),
            json!("top1000")
        );
        assert_eq!(serde_json::to_value(PortMode::Full).unwrap(), json!("full"));
    }
}
