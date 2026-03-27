use crate::OriginCandidate;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::str::FromStr;

/// Scan common DNS records (MX, TXT, SPF) that might leak the origin IP directly.
/// CDNs usually only proxy web traffic (A/CNAME on the apex/www).
pub async fn scan(domain: String) -> anyhow::Result<Vec<OriginCandidate>> {
    let mut candidates = Vec::new();
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    // 1. Check MX records (Mail servers often sit on the origin IP or nearby subnet)
    if let Ok(mx_lookup) = resolver.mx_lookup(domain.clone()).await {
        for mx in mx_lookup {
            let exchange = mx.exchange().to_string();
            if let Ok(a_lookup) = resolver.ipv4_lookup(&exchange).await {
                for ip in a_lookup {
                    candidates.push(OriginCandidate {
                        ip: std::net::IpAddr::V4(ip.0),
                        method: format!("dns_misconfig_mx_a ({})", exchange),
                        confidence: 60, // Moderate confidence — it's an origin asset, maybe not the webserver
                    });
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
                        candidates.push(OriginCandidate {
                            ip: std::net::IpAddr::V4(ip),
                            method: "dns_misconfig_spf_ip4".to_string(),
                            confidence: 85, // High confidence — it's an authorized mail sender block, likely the origin
                        });
                    }
                }
            }
        }
    }

    // 3. Scan common bypass subdomains (direct, origin, mail, ftp) that bypass the CDN
    let bypass_subs = ["direct", "origin", "mail", "ftp", "cpanel"];
    for sub in bypass_subs {
        let fqdn = format!("{}.{}", sub, domain);
        if let Ok(a_lookup) = resolver.ipv4_lookup(&fqdn).await {
            for ip in a_lookup {
                // Filter out common Cloudflare/CDN IPs here (future refinement)
                candidates.push(OriginCandidate {
                    ip: std::net::IpAddr::V4(ip.0),
                    method: format!("dns_misconfig_bypass_sub ({})", fqdn),
                    confidence: 75,
                });
            }
        }
    }

    Ok(candidates)
}
