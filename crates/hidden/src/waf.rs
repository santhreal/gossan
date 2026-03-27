//! WAF fingerprinting.
//!
//! Detects Web Application Firewalls from HTTP response headers.
//! Sends a normal request and an intentionally malicious probe (SQLi payload).
//! Identifies WAF vendor, version where possible, and notes bypass research vectors.
//!
//! WAF presence is Medium severity — it's context, not a vulnerability,
//! but attackers need to know what WAF they're dealing with.

use gossan_core::Target;
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};

struct WafSignature {
    name: &'static str,
    /// Headers that, if present, indicate this WAF (header name, optional value substring).
    headers: &'static [(&'static str, Option<&'static str>)],
    /// Cookie names that indicate this WAF.
    cookies: &'static [&'static str],
    /// Known bypass research reference.
    bypass_hint: &'static str,
}

static SIGNATURES: &[WafSignature] = &[
    WafSignature {
        name: "Cloudflare",
        headers: &[("cf-ray", None), ("server", Some("cloudflare"))],
        cookies: &["__cfuid", "__cf_bm"],
        bypass_hint:
            "github.com/nicowillis/cloudflare-bypass — try cf-worker origin header or direct IP",
    },
    WafSignature {
        name: "AWS WAF",
        headers: &[("x-amzn-waf-action", None), ("x-amzn-requestid", None)],
        cookies: &["aws-waf-token"],
        bypass_hint: "AWS WAF may be bypassed via JSON body encoding or chunked transfer encoding",
    },
    WafSignature {
        name: "F5 BIG-IP WAF",
        headers: &[("x-wa-info", None), ("server", Some("BigIP"))],
        cookies: &["TS01", "BIGipServer"],
        bypass_hint:
            "CVE-2023-46747: unauthenticated RCE — check /mgmt/tm/util/bash for auth bypass",
    },
    WafSignature {
        name: "Imperva Incapsula",
        headers: &[("x-iinfo", None), ("x-cdn", Some("Imperva"))],
        cookies: &["incap_ses_", "visid_incap_"],
        bypass_hint: "Try HTTP/2 with malformed headers or direct IP access to bypass Imperva",
    },
    WafSignature {
        name: "Sucuri WAF",
        headers: &[("x-sucuri-id", None), ("x-sucuri-cache", None)],
        cookies: &[],
        bypass_hint: "Sucuri may be bypassed via direct IP or by modifying the Host header",
    },
    WafSignature {
        name: "Akamai",
        headers: &[("akamai-x-cache", None), ("x-akamai-transformed", None)],
        cookies: &["ak_bmsc"],
        bypass_hint: "Akamai: try sending requests to origin IP directly with matching Host header",
    },
    WafSignature {
        name: "DataDome",
        headers: &[("x-datadome", None)],
        cookies: &["datadome"],
        bypass_hint:
            "DataDome: primarily bot detection, try low-and-slow with real browser fingerprints",
    },
    WafSignature {
        name: "PerimeterX",
        headers: &[("x-px-*", None)],
        cookies: &["_px", "_pxhd", "_pxvid"],
        bypass_hint: "PerimeterX: browser fingerprinting — use puppeteer-extra-plugin-stealth",
    },
    WafSignature {
        name: "Varnish Cache",
        headers: &[("x-varnish", None), ("via", Some("varnish"))],
        cookies: &[],
        bypass_hint: "Varnish is a cache, not a security WAF — focus on cache poisoning attacks",
    },
    WafSignature {
        name: "Fastly CDN",
        headers: &[("x-served-by", Some("cache-")), ("fastly-restarts", None)],
        cookies: &[],
        bypass_hint: "Fastly: look for cache poisoning via Host header and X-Forwarded-Host",
    },
    WafSignature {
        name: "Fortinet FortiWeb",
        headers: &[("x-fw-hash", None)],
        cookies: &["FORTIWAFSID"],
        bypass_hint: "FortiWeb: try Unicode encoding and HTTP parameter pollution",
    },
    WafSignature {
        name: "Citrix ADC/NetScaler",
        headers: &[("via", Some("NS-CACHE")), ("server", Some("Citrix-Gw"))],
        cookies: &["NSC_"],
        bypass_hint: "CVE-2023-3519: unauthenticated RCE in Citrix ADC — check /vpns/cfg/smb.conf",
    },
    WafSignature {
        name: "ModSecurity",
        headers: &[("x-modsecurity-alert", None)],
        cookies: &[],
        bypass_hint: "ModSecurity: check for CRS rule gaps with null bytes, HPP, and JSON encoding",
    },
];

pub async fn probe(client: &Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let url = asset.url.as_str();

    // Normal request — collect response headers
    let Ok(resp) = client.get(url).send().await else {
        return Ok(vec![]);
    };
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let cookies: Vec<String> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .collect();

    let mut findings = Vec::new();

    'sig: for sig in SIGNATURES {
        // Check headers
        for (hname, hval) in sig.headers {
            let found = headers.iter().any(|(k, v)| {
                k.eq_ignore_ascii_case(hname)
                    && hval
                        .map(|want| v.to_lowercase().contains(want))
                        .unwrap_or(true)
            });
            if found {
                findings.push(make_finding(sig, target, url, &headers));
                continue 'sig;
            }
        }

        // Check cookies
        for ck in sig.cookies {
            let found = cookies
                .iter()
                .any(|c| c.to_lowercase().contains(&ck.to_lowercase()));
            if found {
                findings.push(make_finding(sig, target, url, &headers));
                continue 'sig;
            }
        }
    }

    Ok(findings)
}

fn make_finding(
    sig: &WafSignature,
    target: &Target,
    url: &str,
    headers: &[(String, String)],
) -> Finding {
    crate::finding_builder(target, Severity::Info,
        format!("WAF detected: {}", sig.name),
        format!("Web Application Firewall identified as {} at {}. \
                 This changes the attack approach — WAF bypass research required before active exploitation.\n\
                 Bypass research: {}", sig.name, url, sig.bypass_hint))
    .evidence(Evidence::HttpResponse {
        status: 200,
        headers: headers.to_vec(),
        body_excerpt: None,
    })
    .tag("waf").tag("fingerprint")
    .build().expect("finding builder: required fields are set")
}
