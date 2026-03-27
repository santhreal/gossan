//! Shared DNS resolver construction.

use gossan_core::Config;
use hickory_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

/// Build a [`TokioAsyncResolver`] from scan config.
///
/// Uses the configured resolvers if present, otherwise falls back to Cloudflare
/// (1.1.1.1 / 1.0.0.1) for reliability and speed.
pub fn build_resolver(config: &Config) -> anyhow::Result<TokioAsyncResolver> {
    let servers = if config.resolvers.is_empty() {
        NameServerConfigGroup::cloudflare()
    } else {
        NameServerConfigGroup::from_ips_clear(&config.resolvers, 53, true)
    };
    let rc = ResolverConfig::from_parts(None, vec![], servers);
    let mut opts = ResolverOpts::default();
    opts.timeout = config.timeout();
    opts.attempts = 2;
    Ok(TokioAsyncResolver::tokio(rc, opts))
}

/// Look up TXT records for a domain, returning the concatenated text content.
pub async fn lookup_txt(
    resolver: &TokioAsyncResolver,
    name: &str,
) -> anyhow::Result<Vec<String>> {
    let lookup = resolver.txt_lookup(name).await?;
    let records: Vec<String> = lookup
        .iter()
        .flat_map(|txt| txt.iter().map(|d| String::from_utf8_lossy(d).to_string()))
        .collect();
    Ok(records)
}
