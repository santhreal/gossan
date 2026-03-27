mod output;
mod pipeline;

use clap::{Parser, Subcommand};
use gossan_core::{ApiKeys, Config, ModuleConfig, OutputConfig, OutputFormat, PortMode, Severity};
use tracing_subscriber::EnvFilter;

/// Read targets from stdin (one per line) when the target argument is "-".
fn targets_from_stdin() -> Vec<String> {
    scantarget::TargetList::from_stdin()
        .unwrap_or_default()
        .into_iter()
        .map(|t| t.to_string())
        .collect()
}

#[derive(Parser)]
#[command(
    name    = "gossan",
    version,
    about   = "Attack surface discovery — subdomains, ports, tech stack, JS secrets, hidden endpoints, cloud assets",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    // ── Output ─────────────────────────────────────────────────────────────
    #[arg(
        long,
        default_value = "text",
        global = true,
        help = "Output format: text | json | jsonl | sarif | markdown"
    )]
    format: String,
    #[arg(long, global = true, help = "Write output to file instead of stdout")]
    out: Option<String>,

    // ── Tuning ─────────────────────────────────────────────────────────────
    #[arg(
        long,
        default_value = "300",
        global = true,
        help = "Max requests per second"
    )]
    rate: u32,
    #[arg(
        long,
        default_value = "10",
        global = true,
        help = "Per-request timeout in seconds"
    )]
    timeout: u64,
    #[arg(
        long,
        default_value = "150",
        global = true,
        help = "Max concurrent tasks"
    )]
    concurrency: usize,
    #[arg(
        long,
        global = true,
        help = "Minimum severity to report: info | low | medium | high | critical"
    )]
    min_severity: Option<String>,
    #[arg(
        long,
        global = true,
        help = "HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)"
    )]
    proxy: Option<String>,
    #[arg(long, global = true, help = "Cookie header for authenticated crawling")]
    cookie: Option<String>,
    #[arg(
        long,
        global = true,
        value_delimiter = ',',
        help = "Custom DNS resolvers (comma-separated IPs, e.g. 1.1.1.1,8.8.8.8)"
    )]
    resolvers: Vec<String>,

    // ── Port mode ──────────────────────────────────────────────────────────
    #[arg(
        long,
        global = true,
        help = "Ports to scan: default | top100 | top1000 | full | 22,80,443,…"
    )]
    ports: Option<String>,

    // ── API keys (also read from env vars) ──
    #[arg(long, global = true, env = "VT_API_KEY", help = "VirusTotal API key")]
    vt_key: Option<String>,
    #[arg(long, global = true, env = "ST_API_KEY", help = "SecurityTrails API key")]
    st_key: Option<String>,
    #[arg(long, global = true, env = "SHODAN_API_KEY", help = "Shodan API key")]
    shodan_key: Option<String>,
    #[arg(long, global = true, env = "GITHUB_TOKEN", help = "GitHub token for code-search subdomain discovery")]
    github_token: Option<String>,
    #[arg(long, global = true, env = "CENSYS_API_KEY", help = "Censys API key (format: api_id:api_secret)")]
    censys_key: Option<String>,
    #[arg(long, global = true, env = "BINARYEDGE_API_KEY", help = "BinaryEdge API key")]
    binaryedge_key: Option<String>,
    #[arg(long, global = true, env = "FULLHUNT_API_KEY", help = "FullHunt API key")]
    fullhunt_key: Option<String>,
    #[arg(long, global = true, env = "CHAOS_API_KEY", help = "Chaos (ProjectDiscovery) API key")]
    chaos_key: Option<String>,
    #[arg(long, global = true, env = "BEVIGIL_API_KEY", help = "Bevigil API key")]
    bevigil_key: Option<String>,
    #[arg(long, global = true, env = "FOFA_API_KEY", help = "FOFA API key (format: email:key)")]
    fofa_key: Option<String>,
    #[arg(long, global = true, env = "HUNTER_API_KEY", help = "Hunter.io API key")]
    hunter_key: Option<String>,
    #[arg(long, global = true, env = "NETLAS_API_KEY", help = "Netlas API key")]
    netlas_key: Option<String>,
    #[arg(long, global = true, env = "ZOOMEYE_API_KEY", help = "ZoomEye API key")]
    zoomeye_key: Option<String>,
    #[arg(long, global = true, env = "C99_API_KEY", help = "C99 API key")]
    c99_key: Option<String>,
    #[arg(long, global = true, env = "QUAKE_API_KEY", help = "Quake (360) API key")]
    quake_key: Option<String>,
    #[arg(long, global = true, env = "THREATBOOK_API_KEY", help = "ThreatBook API key")]
    threatbook_key: Option<String>,

    // ── Checkpoint / resume ────────────────────────────────────────────────
    #[arg(
        long,
        global = true,
        help = "Path to checkpoint SQLite file (enables save/resume)"
    )]
    checkpoint: Option<String>,
    #[arg(long, global = true, help = "Resume a previous scan by UUID")]
    resume: Option<String>,
}

#[derive(Subcommand)]
enum Command {
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
        #[cfg(feature = "synscan")]
        #[arg(long, help = "Skip SYN port scanning module")]
        no_synscan: bool,
        #[cfg(feature = "headless")]
        #[arg(long, help = "Skip headless browser module")]
        no_headless: bool,
        #[cfg(feature = "crawl")]
        #[arg(long, help = "Skip web crawling module")]
        no_crawl: bool,
    },

    // Individual module subcommands — only compiled in when the feature is active
    #[cfg(feature = "subdomain")]
    /// Subdomain discovery (CT + Wayback + HackerTarget + RapidDNS + OTX + Urlscan + CommonCrawl + bruteforce)
    Subdomain { target: String },

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

    #[cfg(feature = "synscan")]
    /// Raw socket SYN port scan (requires root)
    Synscan { target: String },

    #[cfg(feature = "headless")]
    /// JS rendering and dynamic XHR trapping via Headless Chromium
    Headless { target: String },

    #[cfg(feature = "crawl")]
    /// Authenticated web crawling — form extraction, parameter discovery
    Crawl { target: String },

    /// List saved checkpoint scans
    #[cfg(feature = "checkpoint")]
    ListScans {
        #[arg(long, help = "Checkpoint file path")]
        checkpoint: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install ring as the process-wide rustls crypto provider.
    // Required when multiple rustls backends (ring + aws-lc-rs) are both
    // transitively enabled — reqwest/rustls-tls pulls in aws-lc-rs while the
    // portscan TLS prober uses ring directly.
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("gossan=info".parse()?))
        .with_target(false)
        .compact()
        .init();

    let cli = Cli::parse();

    let format = match cli.format.as_str() {
        "json" => OutputFormat::Json,
        "jsonl" => OutputFormat::Jsonl,
        "sarif" => OutputFormat::Sarif,
        "markdown" | "md" => OutputFormat::Markdown,
        _ => OutputFormat::Text,
    };

    let min_severity = cli.min_severity.as_deref().and_then(|s| match s {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    });

    let port_mode = parse_port_mode(cli.ports.as_deref());

    let api_keys = ApiKeys {
        virustotal: cli.vt_key,
        securitytrails: cli.st_key,
        shodan: cli.shodan_key,
        github: cli.github_token,
        censys: cli.censys_key,
        binaryedge: cli.binaryedge_key,
        fullhunt: cli.fullhunt_key,
        chaos: cli.chaos_key,
        bevigil: cli.bevigil_key,
        fofa: cli.fofa_key,
        hunter: cli.hunter_key,
        netlas: cli.netlas_key,
        zoomeye: cli.zoomeye_key,
        c99: cli.c99_key,
        quake: cli.quake_key,
        threatbook: cli.threatbook_key,
    }
    .resolve(); // merge with env vars

    let resolvers: Vec<std::net::IpAddr> = cli
        .resolvers
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    let mut config = Config {
        rate_limit: cli.rate,
        timeout_secs: cli.timeout,
        concurrency: cli.concurrency,
        output: OutputConfig {
            format,
            path: cli.out,
        },
        min_severity,
        proxy: cli.proxy,
        cookie: cli.cookie,
        port_mode,
        api_keys,
        resolvers,
        ..Config::default()
    };

    match cli.command {
        Command::Scan {
            target,
            #[cfg(feature = "subdomain")]
            no_subdomain,
            #[cfg(feature = "portscan")]
            no_ports,
            #[cfg(feature = "techstack")]
            no_tech,
            #[cfg(feature = "dns")]
            no_dns,
            #[cfg(feature = "js")]
            no_js,
            #[cfg(feature = "hidden")]
            no_hidden,
            #[cfg(feature = "cloud")]
            no_cloud,
            #[cfg(feature = "synscan")]
            no_synscan,
            #[cfg(feature = "headless")]
            no_headless,
            #[cfg(feature = "crawl")]
            no_crawl,
        } => {
            config.modules = ModuleConfig {
                #[cfg(feature = "subdomain")]
                subdomain: !no_subdomain,
                #[cfg(not(feature = "subdomain"))]
                subdomain: false,
                #[cfg(feature = "portscan")]
                portscan: !no_ports,
                #[cfg(not(feature = "portscan"))]
                portscan: false,
                #[cfg(feature = "techstack")]
                techstack: !no_tech,
                #[cfg(not(feature = "techstack"))]
                techstack: false,
                #[cfg(feature = "dns")]
                dns: !no_dns,
                #[cfg(not(feature = "dns"))]
                dns: false,
                #[cfg(feature = "js")]
                js: !no_js,
                #[cfg(not(feature = "js"))]
                js: false,
                #[cfg(feature = "hidden")]
                hidden: !no_hidden,
                #[cfg(not(feature = "hidden"))]
                hidden: false,
                #[cfg(feature = "cloud")]
                cloud: !no_cloud,
                #[cfg(not(feature = "cloud"))]
                cloud: false,
                #[cfg(feature = "synscan")]
                synscan: !no_synscan,
                #[cfg(not(feature = "synscan"))]
                synscan: false,
                #[cfg(feature = "headless")]
                headless: !no_headless,
                #[cfg(not(feature = "headless"))]
                headless: false,
                #[cfg(feature = "crawl")]
                crawl: !no_crawl,
                #[cfg(not(feature = "crawl"))]
                crawl: false,
            };
            let seeds = if target == "-" {
                targets_from_stdin()
            } else {
                vec![target]
            };
            let output_config = config.output.clone();
            let mut all = Vec::new();
            for seed in &seeds {
                all.extend(
                    pipeline::run_full(
                        seed,
                        config.clone(),
                        cli.checkpoint.as_deref(),
                        cli.resume.as_deref(),
                    )
                    .await?,
                );
            }
            output::print_findings(&all, &output_config);
        }

        #[cfg(feature = "subdomain")]
        Command::Subdomain { target } => {
            let output_config = config.output.clone();
            let findings = pipeline::run_module(&target, "subdomain", config).await?;
            output::print_findings(&findings, &output_config);
        }
        #[cfg(feature = "portscan")]
        Command::Ports { target } => {
            let output_config = config.output.clone();
            let findings = pipeline::run_module(&target, "portscan", config).await?;
            output::print_findings(&findings, &output_config);
        }
        #[cfg(feature = "techstack")]
        Command::Tech { target } => {
            let output_config = config.output.clone();
            let findings = pipeline::run_module(&target, "techstack", config).await?;
            output::print_findings(&findings, &output_config);
        }
        #[cfg(feature = "dns")]
        Command::Dns { target } => {
            let output_config = config.output.clone();
            let findings = pipeline::run_module(&target, "dns", config).await?;
            output::print_findings(&findings, &output_config);
        }
        #[cfg(feature = "js")]
        Command::Js { target } => {
            let output_config = config.output.clone();
            let findings = pipeline::run_module(&target, "js", config).await?;
            output::print_findings(&findings, &output_config);
        }
        #[cfg(feature = "hidden")]
        Command::Hidden { target } => {
            let output_config = config.output.clone();
            let findings = pipeline::run_module(&target, "hidden", config).await?;
            output::print_findings(&findings, &output_config);
        }
        #[cfg(feature = "cloud")]
        Command::Cloud { target } => {
            let output_config = config.output.clone();
            let findings = pipeline::run_module(&target, "cloud", config).await?;
            output::print_findings(&findings, &output_config);
        }
        #[cfg(feature = "synscan")]
        Command::Synscan { target } => {
            let output_config = config.output.clone();
            let findings = pipeline::run_module(&target, "synscan", config).await?;
            output::print_findings(&findings, &output_config);
        }
        #[cfg(feature = "headless")]
        Command::Headless { target } => {
            let output_config = config.output.clone();
            let findings = pipeline::run_module(&target, "headless", config).await?;
            output::print_findings(&findings, &output_config);
        }
        #[cfg(feature = "crawl")]
        Command::Crawl { target } => {
            let output_config = config.output.clone();
            let findings = pipeline::run_module(&target, "crawl", config).await?;
            output::print_findings(&findings, &output_config);
        }

        #[cfg(feature = "checkpoint")]
        Command::ListScans { checkpoint } => {
            let path = checkpoint
                .or(cli.checkpoint)
                .unwrap_or_else(|| "gossan.db".to_string());
            let store = gossan_checkpoint::CheckpointStore::open(&path)?;
            for (id, seed, ts) in store.list_scans()? {
                println!("{}\t{}\t{}", id, seed, ts);
            }
        }
    }

    Ok(())
}

fn parse_port_mode(s: Option<&str>) -> PortMode {
    match s {
        None | Some("default") => PortMode::Default,
        Some("top100") => PortMode::Top100,
        Some("top1000") => PortMode::Top1000,
        Some("full") => PortMode::Full,
        Some(custom) => {
            let ports: Vec<u16> = custom
                .split(',')
                .filter_map(|p| p.trim().parse::<u16>().ok())
                .collect();
            if ports.is_empty() {
                PortMode::Default
            } else {
                PortMode::Custom(ports)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_mode() {
        assert!(matches!(parse_port_mode(None), PortMode::Default));
        assert!(matches!(
            parse_port_mode(Some("default")),
            PortMode::Default
        ));
        assert!(matches!(parse_port_mode(Some("top100")), PortMode::Top100));
        assert!(matches!(
            parse_port_mode(Some("top1000")),
            PortMode::Top1000
        ));
        assert!(matches!(parse_port_mode(Some("full")), PortMode::Full));

        let custom = parse_port_mode(Some("80, 443, 8080"));
        if let PortMode::Custom(ports) = custom {
            assert_eq!(ports, vec![80, 443, 8080]);
        } else {
            panic!("Expected Custom mode");
        }

        let empty_custom = parse_port_mode(Some("invalid, ports"));
        assert!(matches!(empty_custom, PortMode::Default));
    }

    #[test]
    fn parse_port_mode_ignores_invalid_entries_inside_custom_lists() {
        let custom = parse_port_mode(Some("80, invalid, 443"));
        let PortMode::Custom(ports) = custom else {
            panic!("expected custom mode");
        };
        assert_eq!(ports, vec![80, 443]);
    }

    #[test]
    fn cli_parses_markdown_alias() {
        let cli = Cli::parse_from(["gossan", "--format", "md", "scan", "example.com"]);
        assert_eq!(cli.format, "md");
    }
}
