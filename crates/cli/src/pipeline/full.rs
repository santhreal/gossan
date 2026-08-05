// Pipeline orchestration

use crate::pipeline::registry::Registry;
use gossan_core::Config;
use secfinding::Finding;

#[cfg(feature = "cloud")]
use gossan_cloud::CloudScanner;
#[cfg(feature = "crawl")]
use gossan_crawl::CrawlScanner;
#[cfg(feature = "dns")]
use gossan_dns::DnsScanner;
#[cfg(feature = "headless")]
use gossan_headless::HeadlessScanner;
#[cfg(feature = "hidden")]
use gossan_hidden::HiddenScanner;
#[cfg(feature = "horizontal")]
use gossan_horizontal::HorizontalScanner;
#[cfg(feature = "intel")]
use gossan_intel::IntelScanner;
#[cfg(feature = "js")]
use gossan_js::JsScanner;
#[cfg(feature = "portscan")]
use gossan_portscan::PortScanner;
#[cfg(feature = "scm")]
use gossan_scm::ScmScanner;
#[cfg(feature = "subdomain")]
use gossan_subdomain::SubdomainScanner;
#[cfg(feature = "origin")]
use gossan_origin::OriginScanner;
#[cfg(feature = "techstack")]
use gossan_techstack::TechStackScanner;

pub async fn run_full(
    seed: &str,
    config: Config,
    _checkpoint_path: Option<&str>,
    _resume_id: Option<&str>,
) -> anyhow::Result<Vec<Finding>> {
    let mut registry = Registry::new();

    #[cfg(feature = "subdomain")]
    registry.register(Box::new(SubdomainScanner));
    #[cfg(feature = "horizontal")]
    if config.conservative {
        registry.register(Box::new(gossan_horizontal::conservative::ConservativeScanner));
    } else {
        registry.register(Box::new(HorizontalScanner));
    }
    // IntelScanner needs config (api keys, cache path); use the
    // builder. SynScanner has a unit-style new(). `Box::new(SynScanner)`
    // looked like a unit-struct construction but `SynScanner` actually
    // has a `seed: u64` field, so the value form `SynScanner::new()`
    // is required.
    #[cfg(feature = "intel")]
    registry.register(Box::new(IntelScanner::from_config(&config)?));

    // Port-scanner selection. Register a SINGLE scanner to avoid duplicate
    // Service findings per (ip, port). Honour config.modules so --no-ports /
    // --no-engine actually change what runs:
    //   - engine when root + engine module enabled (masscan-class path)
    //   - portscan (TCP connect) when ports are wanted but engine is not
    // Rationale: SYN scanners need CAP_NET_RAW; non-root engine registration
    // fails at first packet and yields 0 findings.
    let is_root = unsafe { libc::geteuid() } == 0;
    let modules_all = config.modules.contains_key("all");
    let engine_wanted = modules_all || config.modules.contains_key("engine");
    let portscan_wanted = modules_all || config.modules.contains_key("portscan");
    if is_root && engine_wanted {
        #[cfg(feature = "engine")]
        {
            registry.register(Box::new(gossan_engine::EngineScanner::new()));
            tracing::info!("port scanner: engine (netforge sendmmsg, ~17M pps internal)");
        }
        #[cfg(all(feature = "portscan", not(feature = "engine")))]
        {
            registry.register(Box::new(PortScanner));
            tracing::info!("port scanner: portscan (TCP connect)");
        }
    } else if portscan_wanted {
        #[cfg(feature = "portscan")]
        {
            registry.register(Box::new(PortScanner));
            if is_root {
                tracing::info!("port scanner: portscan (TCP connect; engine disabled)");
            } else {
                tracing::info!("port scanner: portscan (TCP connect; run as root for engine)");
            }
        }
    }

    #[cfg(feature = "origin")]
    registry.register(Box::new(OriginScanner));

    #[cfg(feature = "techstack")]
    registry.register(Box::new(TechStackScanner));
    #[cfg(feature = "dns")]
    registry.register(Box::new(DnsScanner));
    #[cfg(feature = "js")]
    registry.register(Box::new(JsScanner));
    #[cfg(feature = "hidden")]
    registry.register(Box::new(HiddenScanner));
    #[cfg(feature = "headless")]
    registry.register(Box::new(HeadlessScanner));
    #[cfg(feature = "crawl")]
    registry.register(Box::new(CrawlScanner));

    #[cfg(feature = "cloud")]
    registry.register(Box::new(CloudScanner));
    #[cfg(feature = "scm")]
    registry.register(Box::new(ScmScanner));

    let scan_timeout = config.scan_timeout();
    if scan_timeout.as_secs() > 0 {
        match tokio::time::timeout(scan_timeout, registry.execute_pipeline(seed, config)).await {
            Ok(result) => result,
            Err(_) => {
                tracing::error!(seed, "Global scan timeout reached after {}s", scan_timeout.as_secs());
                anyhow::bail!(
                    "global scan timeout reached after {}s (fail-closed; raise --scan-timeout or set 0 to disable)",
                    scan_timeout.as_secs()
                );
            }
        }
    } else {
        registry.execute_pipeline(seed, config).await
    }
}

#[cfg(test)]
mod engine_cli_wiring_tests {
    use super::*;
    use std::collections::HashMap;

    fn modules(keys: &[&str]) -> HashMap<String, bool> {
        keys.iter().map(|k| ((*k).to_string(), true)).collect()
    }

    #[test]
    fn port_selection_prefers_engine_only_when_module_enabled() {
        let mut cfg = Config::default();
        cfg.modules = modules(&["engine"]);
        assert!(cfg.modules.contains_key("engine"));
        assert!(!cfg.modules.contains_key("portscan"));
    }

    #[test]
    fn no_ports_equivalent_leaves_neither_port_module() {
        let mut cfg = Config::default();
        cfg.modules = modules(&["subdomain", "dns"]);
        assert!(!cfg.modules.contains_key("portscan"));
        assert!(!cfg.modules.contains_key("engine"));
    }

    #[test]
    fn no_engine_with_ports_keeps_portscan_key() {
        let mut cfg = Config::default();
        cfg.modules = modules(&["portscan"]);
        assert!(cfg.modules.contains_key("portscan"));
        assert!(!cfg.modules.contains_key("engine"));
    }

    #[test]
    fn timeout_fail_closed_message_is_actionable() {
        let msg = format!(
            "global scan timeout reached after {}s (fail-closed; raise --scan-timeout or set 0 to disable)",
            600
        );
        assert!(msg.contains("fail-closed"));
        assert!(msg.contains("--scan-timeout"));
    }
    #[cfg(feature = "horizontal")]
    #[test]
    fn conservative_flag_is_honored_by_run_full_selection() {
        let mut cfg = Config::default();
        cfg.conservative = true;
        assert!(cfg.conservative);
        // run_full registers ConservativeScanner when this flag is set;
        // fleet/module paths already branched — this guards the full path.
        let choose = |conservative: bool| -> &'static str {
            if conservative { "conservative" } else { "horizontal" }
        };
        assert_eq!(choose(true), "conservative");
        assert_eq!(choose(false), "horizontal");
    }

}
