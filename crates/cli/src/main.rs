//! Gossan CLI entry point — parses arguments, builds config, runs pipeline.

mod output;
mod pipeline;
use pipeline::{exec_module, resolve_targets};

use clap::Parser;
use gossan_core::{ApiKeys, Config, ModuleConfig, OutputConfig, OutputFormat, PortMode, Severity};
use tracing_subscriber::EnvFilter;

mod args;
use args::*;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install ring as the process-wide rustls crypto provider.
    // Required when multiple rustls backends (ring + aws-lc-rs) are both
    // transitively enabled — reqwest/rustls-tls pulls in aws-lc-rs while the
    // portscan TLS prober uses ring directly.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Structured logging: when GOSSAN_LOG_JSON=1 emit one JSON event
    // per line (operator-facing — pipe into Loki/CloudWatch/Datadog).
    // Default stays compact for human terminal use.
    let json_logs = std::env::var("GOSSAN_LOG_JSON").is_ok_and(|v| v == "1" || v == "true");
    if json_logs {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env().add_directive("gossan=info".parse()?))
            .with_target(false)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env().add_directive("gossan=info".parse()?))
            .with_target(false)
            .compact()
            .init();
    }

    let cli = Cli::parse();

    let mut config = cli.build_config();

    #[cfg(feature = "portscan")]
    {
        let nvd_path = cli
            .nvd_db
            .clone()
            .or_else(|| std::env::var("NVD_DB_PATH").ok())
            .map(std::path::PathBuf::from);
        gossan_portscan::cve::nvd::init(nvd_path);
    }

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
            #[cfg(feature = "headless")]
            no_headless,
            #[cfg(feature = "crawl")]
            no_crawl,
            #[cfg(feature = "origin")]
            no_origin,
            #[cfg(feature = "horizontal")]
            no_horizontal,
            #[cfg(feature = "graph")]
            no_graph,
            #[cfg(feature = "scm")]
            no_scm,
            #[cfg(feature = "intel")]
            no_intel,
            #[cfg(feature = "fleet")]
            no_fleet,
            #[cfg(feature = "engine")]
            no_engine,
        } => {
            let mut active_modules = std::collections::HashMap::new();
            #[cfg(feature = "subdomain")]
            if !no_subdomain {
                active_modules.insert("subdomain".to_string(), true);
            }
            #[cfg(feature = "portscan")]
            if !no_ports {
                active_modules.insert("portscan".to_string(), true);
            }
            #[cfg(feature = "techstack")]
            if !no_tech {
                active_modules.insert("techstack".to_string(), true);
            }
            #[cfg(feature = "dns")]
            if !no_dns {
                active_modules.insert("dns".to_string(), true);
            }
            #[cfg(feature = "js")]
            if !no_js {
                active_modules.insert("js".to_string(), true);
            }
            #[cfg(feature = "hidden")]
            if !no_hidden {
                active_modules.insert("hidden".to_string(), true);
            }
            #[cfg(feature = "cloud")]
            if !no_cloud {
                active_modules.insert("cloud".to_string(), true);
            }
            #[cfg(feature = "headless")]
            if !no_headless {
                active_modules.insert("headless".to_string(), true);
            }
            #[cfg(feature = "crawl")]
            if !no_crawl {
                active_modules.insert("crawl".to_string(), true);
            }
            #[cfg(feature = "origin")]
            if !no_origin {
                active_modules.insert("origin".to_string(), true);
            }
            #[cfg(feature = "horizontal")]
            if !no_horizontal {
                active_modules.insert("horizontal".to_string(), true);
            }
            #[cfg(feature = "graph")]
            if !no_graph {
                active_modules.insert("graph".to_string(), true);
            }
            #[cfg(feature = "scm")]
            if !no_scm {
                active_modules.insert("scm".to_string(), true);
            }
            #[cfg(feature = "intel")]
            if !no_intel {
                active_modules.insert("intel".to_string(), true);
            }
            #[cfg(feature = "fleet")]
            if !no_fleet {
                active_modules.insert("fleet".to_string(), true);
            }
            #[cfg(feature = "engine")]
            if !no_engine {
                active_modules.insert("engine".to_string(), true);
            }
            config.modules = active_modules;
            let seeds = resolve_targets(target);
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
        Command::Subdomain { target } => exec_module(target, "subdomain", config).await?,
        #[cfg(feature = "horizontal")]
        Command::Horizontal { target } => exec_module(target, "horizontal", config).await?,
        #[cfg(feature = "scm")]
        Command::Scm { target } => exec_module(target, "scm", config).await?,
        #[cfg(feature = "intel")]
        Command::Intel { target } => exec_module(target, "intel", config).await?,
        #[cfg(feature = "fleet")]
        Command::FleetMaster { listen } => {
            gossan_fleet::master::run_master(&listen, &config).await?;
        }
        #[cfg(feature = "fleet")]
        Command::FleetWorker { master } => {
            gossan_fleet::worker::run_worker(&master, &config).await?;
        }
        #[cfg(feature = "portscan")]
        Command::Ports { target } => exec_module(target, "portscan", config).await?,
        #[cfg(feature = "techstack")]
        Command::Tech { target } => exec_module(target, "techstack", config).await?,
        #[cfg(feature = "dns")]
        Command::Dns { target } => exec_module(target, "dns", config).await?,
        #[cfg(feature = "js")]
        Command::Js { target } => exec_module(target, "js", config).await?,
        #[cfg(feature = "hidden")]
        Command::Hidden { target } => exec_module(target, "hidden", config).await?,
        #[cfg(feature = "cloud")]
        Command::Cloud { target } => exec_module(target, "cloud", config).await?,
        #[cfg(feature = "headless")]
        Command::Headless { target } => exec_module(target, "headless", config).await?,
        #[cfg(feature = "crawl")]
        Command::Crawl { target } => exec_module(target, "crawl", config).await?,
        #[cfg(feature = "origin")]
        Command::Origin { target } => exec_module(target, "origin", config).await?,
        #[cfg(feature = "engine")]
        Command::Engine { target } => exec_module(target, "engine", config).await?,

        #[cfg(feature = "engine")]
        Command::ProbeEngine => {
            print!("{}", gossan_engine::probe().render_table());
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
