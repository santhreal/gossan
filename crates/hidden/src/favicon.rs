use gossan_core::Target;
use secfinding::{Finding, Severity};
use std::collections::HashMap;

fn known_hashes() -> HashMap<u32, &'static str> {
    [
        (116323821, "Jenkins"),
        (708762727, "Apache Tomcat"),
        (1820000864, "Kibana"),
        (1768726056, "Grafana"),
        (2112077716, "phpMyAdmin"),
        (812492305, "Jupyter Notebook"),
        (3509854774, "GitLab"),
        (3876078860, "Jira"),
        (434606617, "Confluence"),
        (1307864597, "Elasticsearch"),
        (783822853, "Splunk"),
        (3093228109, "Fortinet"),
        (2091241266, "Cisco"),
        (2040698672, "Citrix"),
    ]
    .into_iter()
    .collect()
}

pub async fn probe(client: &reqwest::Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let base = asset.url.as_str().trim_end_matches('/');
    let url = format!("{}/favicon.ico", base);
    let mut findings = Vec::new();

    if let Ok(resp) = client.get(&url).send().await {
        if resp.status().as_u16() == 200 {
            let bytes = resp.bytes().await?;
            if !bytes.is_empty() {
                let b64 = base64_encode(&bytes);
                let hash = murmurhash3_x86_32(b64.as_bytes(), 0);
                let known = known_hashes();
                if let Some(tech) = known.get(&hash) {
                    findings.push(
                        crate::finding_builder(
                            target, Severity::Info,
                            format!("Favicon identifies: {}", tech),
                            format!("Favicon hash 0x{:08x} matches {} — identified without version headers.", hash, tech),
                        )
                        .tag("favicon").tag("fingerprint")
                        .build().expect("finding builder: required fields are set"),
                    );
                } else {
                    findings.push(
                        crate::finding_builder(
                            target,
                            Severity::Info,
                            "Favicon hash computed",
                            format!(
                                "Favicon hash: 0x{:08x} (Shodan query: http.favicon.hash:{})",
                                hash, hash as i32
                            ),
                        )
                        .tag("favicon")
                        .build()
                        .expect("finding builder: required fields are set"),
                    );
                }
            }
        }
    }

    Ok(findings)
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    let mut col = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() {
            data[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < data.len() {
            data[i + 2] as u32
        } else {
            0
        };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((n >> 18) & 63) as usize] as char);
        out.push(CHARS[((n >> 12) & 63) as usize] as char);
        out.push(if i + 1 < data.len() {
            CHARS[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if i + 2 < data.len() {
            CHARS[(n & 63) as usize] as char
        } else {
            '='
        });
        col += 4;
        if col >= 76 {
            out.push('\n');
            col = 0;
        }
        i += 3;
    }
    out
}

fn murmurhash3_x86_32(data: &[u8], seed: u32) -> u32 {
    let c1: u32 = 0xcc9e2d51;
    let c2: u32 = 0x1b873593;
    let mut h1 = seed;
    let chunks = data.chunks_exact(4);
    let remainder = chunks.remainder();
    for chunk in chunks {
        // Safety: chunks_exact(4) guarantees each chunk is exactly 4 bytes.
        let bytes: [u8; 4] = [chunk[0], chunk[1], chunk[2], chunk[3]];
        let mut k1 = u32::from_le_bytes(bytes);
        k1 = k1.wrapping_mul(c1).rotate_left(15).wrapping_mul(c2);
        h1 ^= k1;
        h1 = h1.rotate_left(13).wrapping_mul(5).wrapping_add(0xe6546b64);
    }
    let mut k1: u32 = 0;
    match remainder.len() {
        3 => {
            k1 ^= (remainder[2] as u32) << 16;
            k1 ^= (remainder[1] as u32) << 8;
            k1 ^= remainder[0] as u32;
        }
        2 => {
            k1 ^= (remainder[1] as u32) << 8;
            k1 ^= remainder[0] as u32;
        }
        1 => {
            k1 ^= remainder[0] as u32;
        }
        _ => {}
    }
    if !remainder.is_empty() {
        k1 = k1.wrapping_mul(c1).rotate_left(15).wrapping_mul(c2);
        h1 ^= k1;
    }
    h1 ^= data.len() as u32;
    h1 ^= h1 >> 16;
    h1 = h1.wrapping_mul(0x85ebca6b);
    h1 ^= h1 >> 13;
    h1 = h1.wrapping_mul(0xc2b2ae35);
    h1 ^= h1 >> 16;
    h1
}
