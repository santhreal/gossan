// Pipeline orchestration

use gossan_core::Config;
use secfinding::Finding;
use crate::pipeline::registry::Registry;

#[cfg(feature = "subdomain")] use gossan_subdomain::SubdomainScanner;
#[cfg(feature = "portscan")] use gossan_portscan::PortScanner;
#[cfg(feature = "techstack")] use gossan_techstack::TechStackScanner;
#[cfg(feature = "dns")] use gossan_dns::DnsScanner;
#[cfg(feature = "js")] use gossan_js::JsScanner;
#[cfg(feature = "hidden")] use gossan_hidden::HiddenScanner;
#[cfg(feature = "headless")] use gossan_headless::HeadlessScanner;
#[cfg(feature = "crawl")] use gossan_crawl::CrawlScanner;
#[cfg(feature = "cloud")] use gossan_cloud::CloudScanner;
#[cfg(feature = "intel")] use gossan_intel::IntelScanner;
#[cfg(feature = "scm")] use gossan_scm::ScmScanner;
#[cfg(feature = "horizontal")] use gossan_horizontal::HorizontalScanner;

pub async fn run_full(
    seed: &str,
    config: Config,
    _checkpoint_path: Option<&str>,
    _resume_id: Option<&str>,
) -> anyhow::Result<Vec<Finding>> {
    let mut registry = Registry::new();

    #[cfg(feature = "subdomain")] registry.register(Box::new(SubdomainScanner));
    #[cfg(feature = "horizontal")] registry.register(Box::new(HorizontalScanner));
    // IntelScanner needs config (api keys, cache path); use the
    // builder. SynScanner has a unit-style new() — `Box::new(SynScanner)`
    // looked like a unit-struct construction but `SynScanner` actually
    // has a `seed: u64` field, so the value form `SynScanner::new()`
    // is required.
    #[cfg(feature = "intel")]
    registry.register(Box::new(IntelScanner::from_config(&config)?));

    // Port-scanner selection. We register a SINGLE scanner instead of
    // all three to avoid duplicate Service findings per (ip, port).
    //
    // Selection ladder, fastest-first:
    //   - engine (netforge SYN, sendmmsg backend, ~17M pps internal)
    //     when running as root — this is the masscan-class path.
    //   - portscan (TCP connect, no privileges) otherwise.
    //
    // Rationale: SYN-based scanners need CAP_NET_RAW. If we register
    // them at non-root they fail at first packet send and every Host
    // target gets 0 findings — worse than just using TCP connect.
    let is_root = unsafe { libc::geteuid() } == 0;
    if is_root {
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
    } else {
        #[cfg(feature = "portscan")]
        {
            registry.register(Box::new(PortScanner));
            tracing::info!("port scanner: portscan (TCP connect; run as root for engine)");
        }
    }
    
    #[cfg(feature = "techstack")] registry.register(Box::new(TechStackScanner));
    #[cfg(feature = "dns")] registry.register(Box::new(DnsScanner));
    #[cfg(feature = "js")] registry.register(Box::new(JsScanner));
    #[cfg(feature = "hidden")] registry.register(Box::new(HiddenScanner));
    #[cfg(feature = "headless")] registry.register(Box::new(HeadlessScanner));
    #[cfg(feature = "crawl")] registry.register(Box::new(CrawlScanner));
    
    #[cfg(feature = "cloud")] registry.register(Box::new(CloudScanner));
    #[cfg(feature = "scm")] registry.register(Box::new(ScmScanner));

    registry.execute_pipeline(seed, config).await
}
