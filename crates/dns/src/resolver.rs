//! Shared DNS resolver construction.
//!
//! Thin re-export of [`gossan_core::net::build_resolver`] so every crate
//! that needs a TokioResolver goes through the single owner in
//! gossan-core (DNSSEC, multi-provider fallback, rebinding TTL pins).

use gossan_core::Config;
use hickory_resolver::TokioResolver;

/// Build a [`TokioResolver`] from scan config.
///
/// Delegates to [`gossan_core::net::build_resolver`].
pub fn build_resolver(config: &Config) -> anyhow::Result<TokioResolver> {
    gossan_core::net::build_resolver(config)
}

/// Look up TXT records for a domain, returning the concatenated text content.
pub async fn lookup_txt(resolver: &TokioResolver, name: &str) -> anyhow::Result<Vec<String>> {
    let lookup = resolver.txt_lookup(name).await?;
    let records: Vec<String> = lookup
        .iter()
        .map(|txt| {
            txt.iter()
                .map(|d| String::from_utf8_lossy(d).to_string())
                .collect::<Vec<String>>()
                .join("")
        })
        .collect();
    Ok(records)
}

/// Outcome of a TXT lookup that distinguishes absence from resolver failure.
#[derive(Debug, Clone)]
pub enum TxtLookup {
    /// One or more TXT strings were returned.
    Records(Vec<String>),
    /// NXDOMAIN / NODATA — the name has no TXT records.
    Absent,
}

/// Look up TXT records, classifying NXDOMAIN/NODATA separately from transient errors.
pub async fn lookup_txt_classified(
    resolver: &TokioResolver,
    name: &str,
) -> anyhow::Result<TxtLookup> {
    match resolver.txt_lookup(name).await {
        Ok(lookup) => {
            let records: Vec<String> = lookup
                .iter()
                .map(|txt| {
                    txt.iter()
                        .map(|d| String::from_utf8_lossy(d).to_string())
                        .collect::<Vec<String>>()
                        .join("")
                })
                .collect();
            if records.is_empty() {
                Ok(TxtLookup::Absent)
            } else {
                Ok(TxtLookup::Records(records))
            }
        }
        Err(e) if e.is_nx_domain() || e.is_no_records_found() => Ok(TxtLookup::Absent),
        Err(e) => Err(e.into()),
    }
}
