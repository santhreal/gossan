use crate::util::is_routable_ip;
use crate::OriginCandidate;
use futures::future::join_all;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use std::net::IpAddr;
use std::str::FromStr;

/// Scan common DNS records (MX, TXT, SPF, DMARC) that might leak the origin IP directly.
/// CDNs usually only proxy web traffic (A/CNAME on the apex/www).
pub async fn scan(domain: String) -> anyhow::Result<Vec<OriginCandidate>> {
    let mut candidates = Vec::new();
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::default(),
        TokioConnectionProvider::default(),
    )
    .with_options(ResolverOpts::default())
    .build();

    // 1. Check MX records (Mail servers often sit on the origin IP or nearby subnet)
    match resolver.mx_lookup(domain.clone()).await {
        Ok(mx_lookup) => {
        for mx in mx_lookup {
            let exchange = mx.exchange().to_string();
            match resolver.ipv4_lookup(&exchange).await {
                Ok(a_lookup) => {
                    for ip in a_lookup {
                        let addr = IpAddr::V4(ip.0);
                        if is_routable_ip(addr) {
                            candidates.push(OriginCandidate::new(
                                addr,
                                format!("dns_misconfig_mx_a ({exchange})"),
                                60,
                            ));
                        }
                    }
                }
                Err(e) if e.is_nx_domain() || e.is_no_records_found() => {}
                Err(e) => {
                    tracing::warn!(
                        exchange = %exchange,
                        error = %e,
                        "dns_misconfig MX A lookup failed; skipping exchange"
                    );
                }
            }
        }
        }
        Err(e) if e.is_nx_domain() || e.is_no_records_found() => {}
        Err(e) => {
            tracing::warn!(domain = %domain, error = %e, "dns_misconfig MX lookup failed");
        }
    }

    // 2. Check TXT records (SPF often lists origin IPv4 ranges: v=spf1 ip4:X.X.X.X)
    match resolver.txt_lookup(domain.clone()).await {
        Ok(txt_lookup) => {
        for txt in txt_lookup {
            let string_data = txt.to_string();
            if string_data.contains("ip4:") {
                let parts = string_data.split("ip4:");
                for p in parts.skip(1) {
                    let ip_str = p.split([' ', '/']).next().unwrap_or("");
                    if let Ok(ip) = std::net::Ipv4Addr::from_str(ip_str) {
                        let addr = IpAddr::V4(ip);
                        if is_routable_ip(addr) {
                            candidates.push(OriginCandidate::new(
                                addr,
                                "dns_misconfig_spf_ip4",
                                85,
                            ));
                        }
                    }
                }
            }
            if string_data.contains("ip6:") {
                let parts = string_data.split("ip6:");
                for p in parts.skip(1) {
                    let ip_str = p.split([' ', '/']).next().unwrap_or("");
                    if let Ok(ip) = std::net::Ipv6Addr::from_str(ip_str) {
                        let addr = IpAddr::V6(ip);
                        if is_routable_ip(addr) {
                            candidates.push(OriginCandidate::new(
                                addr,
                                "dns_misconfig_spf_ip6",
                                85,
                            ));
                        }
                    }
                }
            }
        }
        }
        Err(e) if e.is_nx_domain() || e.is_no_records_found() => {}
        Err(e) => {
            tracing::warn!(domain = %domain, error = %e, "dns_misconfig SPF/TXT lookup failed");
        }
    }

    // 3. DMARC TXT record (_dmarc.domain) → parse RUA domain and resolve it.
    let dmarc_domain = format!("_dmarc.{}", domain);
    match resolver.txt_lookup(&dmarc_domain).await {
        Ok(txt_lookup) => {
        for txt in txt_lookup {
            let string_data = txt.to_string();
            if let Some(rua_domain) = parse_dmarc_rua(&string_data) {
                // Resolve A records for the RUA domain.
                match resolver.ipv4_lookup(&rua_domain).await {
                    Ok(a_lookup) => {
                        for ip in a_lookup {
                            let addr = IpAddr::V4(ip.0);
                            if is_routable_ip(addr) {
                                candidates.push(OriginCandidate::new(
                                    addr,
                                    format!("dns_misconfig_dmarc_rua ({rua_domain})"),
                                    70,
                                ));
                            }
                        }
                    }
                    Err(e) if e.is_nx_domain() || e.is_no_records_found() => {}
                    Err(e) => {
                        tracing::warn!(
                            rua_domain = %rua_domain,
                            error = %e,
                            "dns_misconfig DMARC RUA A lookup failed; skipping"
                        );
                    }
                }
            }
        }
        }
        Err(e) if e.is_nx_domain() || e.is_no_records_found() => {}
        Err(e) => {
            tracing::warn!(domain = %dmarc_domain, error = %e, "dns_misconfig DMARC TXT lookup failed");
        }
    }

    // 4. Scan common bypass subdomains that bypass the CDN concurrently.
    let bypass_subs = [
        "direct", "origin", "mail", "ftp", "cpanel", "staging", "dev", "test", "api", "admin",
        "portal", "app", "beta", "prod", "www",
    ];
    let fqdns: Vec<String> = bypass_subs
        .iter()
        .map(|sub| format!("{}.{}", sub, domain))
        .collect();
    let lookups: Vec<_> = fqdns
        .iter()
        .map(|fqdn| {
            let resolver = resolver.clone();
            let fqdn = fqdn.clone();
            async move {
                match resolver.ipv4_lookup(&fqdn).await {
                    Ok(lookup) => Some(lookup),
                    Err(e) => {
                        // NXDOMAIN / empty is expected for most bypass labels.
                        // Transient resolver failures must not silently erase candidates.
                        if !(e.is_nx_domain() || e.is_no_records_found()) {
                            tracing::warn!(
                                fqdn = %fqdn,
                                error = %e,
                                "dns_misconfig bypass-sub lookup failed; skipping label"
                            );
                        }
                        None
                    }
                }
            }
        })
        .collect();
    for (fqdn, lookup) in fqdns.into_iter().zip(join_all(lookups).await) {
        if let Some(lookup) = lookup {
            for ip in lookup {
                let addr = IpAddr::V4(ip.0);
                if is_routable_ip(addr) {
                    candidates.push(OriginCandidate::new(
                        addr,
                        format!("dns_misconfig_bypass_sub ({fqdn})"),
                        75,
                    ));
                }
            }
        }
    }

    Ok(candidates)
}

/// Parse the RUA domain from a DMARC TXT record string.
/// Returns the domain after the `@` in the RUA email address, if any.
fn parse_dmarc_rua(string_data: &str) -> Option<String> {
    let string_data_lower = string_data.to_lowercase();
    if !string_data_lower.contains("v=dmarc1") {
        return None;
    }
    let rua_start = string_data_lower.find("rua=")?;
    let after_rua = &string_data_lower[rua_start + 4..];
    // DMARC allows size suffixes: rua=mailto:reports@example.com!10m
    let rua_val = after_rua
        .split(|c| c == ';' || c == '!')
        .next()
        .unwrap_or(after_rua)
        .trim();
    let email_part = rua_val.strip_prefix("mailto:").unwrap_or(rua_val);
    let at_pos = email_part.find('@')?;
    Some(email_part[at_pos + 1..].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dmarc_unicode_does_not_panic() {
        // The Turkish dotted capital I (U+0130) lowercases to "i" + combining dot (U+0307),
        // which changes the byte length of the lowercased string relative to the original.
        // Before the fix, using the byte index from the lowercased string to index the
        // original string would panic with "byte index out of bounds".
        let txt = "v=DMARC1; rua=mailto:reports@İexample.com";
        let rua = parse_dmarc_rua(txt);
        // The domain is extracted from the lowercased string, so the Turkish İ
        // becomes "i\u{307}" (i + combining dot above).
        assert_eq!(rua, Some("i\u{0307}example.com".to_string()));
    }

    #[test]
    fn dmarc_basic_parsing() {
        let txt = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com";
        assert_eq!(parse_dmarc_rua(txt), Some("example.com".to_string()));
    }

    #[test]
    fn dmarc_no_rua() {
        let txt = "v=DMARC1; p=reject";
        assert_eq!(parse_dmarc_rua(txt), None);
    }

    #[test]
    fn dmarc_no_at_sign() {
        let txt = "v=DMARC1; rua=mailto:nodomain";
        assert_eq!(parse_dmarc_rua(txt), None);
    }

    #[test]
    fn dmarc_rua_with_size_suffix() {
        let txt = "v=DMARC1; rua=mailto:reports@example.com!10m";
        assert_eq!(parse_dmarc_rua(txt), Some("example.com".to_string()));
    }
}
