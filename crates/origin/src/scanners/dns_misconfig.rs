use crate::util::is_routable_ip;
use crate::OriginCandidate;
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
    if let Ok(mx_lookup) = resolver.mx_lookup(domain.clone()).await {
        for mx in mx_lookup {
            let exchange = mx.exchange().to_string();
            if let Ok(a_lookup) = resolver.ipv4_lookup(&exchange).await {
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
        }
    }

    // 2. Check TXT records (SPF often lists origin IPv4 ranges: v=spf1 ip4:X.X.X.X)
    if let Ok(txt_lookup) = resolver.txt_lookup(domain.clone()).await {
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

    // 3. DMARC TXT record (_dmarc.domain) → parse RUA domain and resolve it.
    let dmarc_domain = format!("_dmarc.{}", domain);
    if let Ok(txt_lookup) = resolver.txt_lookup(&dmarc_domain).await {
        for txt in txt_lookup {
            let string_data = txt.to_string();
            if string_data.to_lowercase().contains("v=dmarc1") {
                // Extract rua=mailto:reports@example.com!10m or rua=mailto:reports@example.com
                if let Some(rua_start) = string_data.to_lowercase().find("rua=") {
                    let after_rua = &string_data[rua_start + 4..];
                    let rua_val = after_rua.split(';').next().unwrap_or(after_rua).trim();
                    // Strip mailto: prefix if present.
                    let email_part = rua_val.strip_prefix("mailto:").unwrap_or(rua_val);
                    // Extract domain after '@'.
                    if let Some(at_pos) = email_part.find('@') {
                        let rua_domain = &email_part[at_pos + 1..];
                        // Resolve A records for the RUA domain.
                        if let Ok(a_lookup) = resolver.ipv4_lookup(rua_domain).await {
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
                    }
                }
            }
        }
    }

    // 4. Scan common bypass subdomains that bypass the CDN.
    let bypass_subs = [
        "direct", "origin", "mail", "ftp", "cpanel", "staging", "dev", "test", "api", "admin",
        "portal", "app", "beta", "prod", "www",
    ];
    for sub in bypass_subs {
        let fqdn = format!("{}.{}", sub, domain);
        if let Ok(a_lookup) = resolver.ipv4_lookup(&fqdn).await {
            for ip in a_lookup {
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
