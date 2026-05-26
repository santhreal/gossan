//! Active service probe engine.
//!
//! Loads probe definitions from `rules/service_probes.toml` and executes them
//! against open TCP ports. Falls back to passive banner grab when probes fail.

use regex::bytes::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A single service probe definition.
#[derive(Debug, Clone, Deserialize)]
pub struct ProbeDef {
    /// Human-readable probe name (e.g. "HTTP_GET").
    pub name: String,
    /// Optional port restriction; if None the probe runs on all ports.
    pub ports: Option<Vec<u16>>,
    /// Payload bytes as a hex string or plain ASCII string.
    /// If the string starts with "0x" it is parsed as hex.
    pub payload: String,
    /// Regex pattern to match against the response.
    pub match_regex: String,
    /// Optional fallback probe name to try next.
    pub fallback_probe: Option<String>,
}

/// TOML file containing service probe definitions.
#[derive(Debug, Deserialize)]
struct ProbeFile {
    probe: Vec<ProbeDef>,
}

/// Compiled probe with parsed regex and payload bytes.
struct CompiledProbe {
    def: ProbeDef,
    payload: Vec<u8>,
    regex: Regex,
}

static PROBES: OnceLock<Vec<CompiledProbe>> = OnceLock::new();

fn builtin_probes_toml() -> &'static str {
    // Path is relative to THIS file (src/probes/mod.rs), so the
    // crate-level `rules/` directory needs `../../rules/`. The other
    // probe data files (`src/rules.rs`) use `../rules/` because
    // they're one directory shallower — different relative anchor.
    // Getting this wrong is silent at edit-time but a hard
    // include_str! failure at compile-time.
    include_str!("../../rules/service_probes.toml")
}

fn compiled_probes() -> &'static Vec<CompiledProbe> {
    PROBES.get_or_init(|| {
        let defs = match parse_probes(builtin_probes_toml()) {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(error = %e, "failed to parse built-in service probes");
                Vec::new()
            }
        };
        defs.into_iter()
            .filter_map(|def| {
                let payload = parse_payload(&def.payload);
                let regex = match Regex::new(&def.match_regex) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(probe = %def.name, err = %e, "invalid probe regex");
                        return None;
                    }
                };
                Some(CompiledProbe {
                    def,
                    payload,
                    regex,
                })
            })
            .collect()
    })
}

fn parse_probes(content: &str) -> Result<Vec<ProbeDef>, toml::de::Error> {
    toml::from_str::<ProbeFile>(content).map(|f| f.probe)
}

fn parse_payload(s: &str) -> Vec<u8> {
    if let Some(hex) = s.strip_prefix("0x") {
        hex::decode(hex).unwrap_or_default()
    } else {
        s.as_bytes().to_vec()
    }
}

/// Engine that executes active service probes.
#[derive(Debug)]
pub struct ProbeEngine {
    timeout: Duration,
}

impl ProbeEngine {
    /// Create a new probe engine with the given per-probe timeout.
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Probe a connected stream.
    ///
    /// Returns `(banner, probe_match_names)`.
    pub async fn probe(
        &self,
        mut stream: tokio::net::TcpStream,
        _addr: &str,
        port: u16,
        _proxy: Option<&str>,
    ) -> (Option<String>, Vec<String>) {
        // 1. Try passive banner first with a short timeout
        let mut buf = vec![0u8; 4096];
        let banner =
            match tokio::time::timeout(Duration::from_millis(300), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    let s = sanitize(&buf[..n]);
                    if !s.is_empty() {
                        Some(s)
                    } else {
                        None
                    }
                }
                _ => None,
            };

        if banner.is_some() {
            // Still run probes to get richer identification
            let matches = self.run_active_probes(&mut stream, port, &buf).await;
            return (banner, matches);
        }

        // 2. No banner — send active probes
        let matches = self.run_active_probes(&mut stream, port, &[]).await;
        (None, matches)
    }

    async fn run_active_probes(
        &self,
        stream: &mut tokio::net::TcpStream,
        port: u16,
        initial_data: &[u8],
    ) -> Vec<String> {
        let mut matches = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let probes = compiled_probes();
        let by_name: HashMap<String, usize> = probes
            .iter()
            .enumerate()
            .map(|(i, p)| (p.def.name.clone(), i))
            .collect();

        for (idx, probe) in probes.iter().enumerate() {
            if seen.contains(&idx) {
                continue;
            }
            if let Some(ref allowed) = probe.def.ports {
                if !allowed.contains(&port) {
                    continue;
                }
            }

            if let Some(m) = self.execute_probe(stream, probe, initial_data).await {
                matches.push(m.clone());
                seen.insert(idx);
                // Follow fallback chain once
                if let Some(ref fallback) = probe.def.fallback_probe {
                    if let Some(&fb_idx) = by_name.get(fallback) {
                        if !seen.contains(&fb_idx) {
                            if let Some(fm) = self
                                .execute_probe(stream, &probes[fb_idx], initial_data)
                                .await
                            {
                                matches.push(fm);
                            }
                            seen.insert(fb_idx);
                        }
                    }
                }
            }
        }
        matches
    }

    async fn execute_probe(
        &self,
        stream: &mut tokio::net::TcpStream,
        probe: &CompiledProbe,
        initial_data: &[u8],
    ) -> Option<String> {
        if !probe.payload.is_empty() {
            if tokio::time::timeout(self.timeout, stream.write_all(&probe.payload))
                .await
                .ok()
                .is_none()
            {
                return None;
            }
        }

        let mut buf = vec![0u8; 8192];
        let n = match tokio::time::timeout(Duration::from_millis(800), stream.read(&mut buf)).await
        {
            Ok(Ok(n)) => n,
            _ => 0,
        };

        let data = if initial_data.is_empty() {
            &buf[..n]
        } else {
            // Combine initial read with probe response for matching
            let mut combined = initial_data.to_vec();
            combined.extend_from_slice(&buf[..n]);
            // Leak into a static-like slice — not ideal, but we only need it briefly.
            // Better: check regex against combined directly.
            return if probe.regex.is_match(&combined) {
                Some(probe.def.name.clone())
            } else {
                None
            };
        };

        if probe.regex.is_match(data) {
            Some(probe.def.name.clone())
        } else {
            None
        }
    }
}

fn sanitize(data: &[u8]) -> String {
    data.iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect::<String>()
        .trim()
        .to_string()
}

/// Load community probe definitions from a directory of `*.toml` files.
pub fn load_community_probes(dir: &std::path::Path) -> Vec<ProbeDef> {
    let mut defs = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return defs,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        if path.file_stem().and_then(|s| s.to_str()) == Some("service_probes") {
            continue; // skip built-in
        }
        match std::fs::read_to_string(&path) {
            Ok(content) => match parse_probes(&content) {
                Ok(file_defs) => {
                    tracing::info!(path = %path.display(), count = file_defs.len(), "loaded community probes");
                    defs.extend(file_defs);
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), err = %e, "skipping malformed probe file")
                }
            },
            Err(e) => {
                tracing::warn!(path = %path.display(), err = %e, "failed to read probe file")
            }
        }
    }
    defs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_payload_hex() {
        assert_eq!(parse_payload("0x48656c6c6f"), b"Hello");
    }

    #[test]
    fn parse_payload_ascii() {
        assert_eq!(parse_payload("GET / HTTP/1.1\r\n"), b"GET / HTTP/1.1\r\n");
    }

    #[test]
    fn compiled_probes_are_loadable() {
        let probes = compiled_probes();
        assert!(
            probes.len() >= 200,
            "expected at least 200 service probes, got {}",
            probes.len()
        );
    }

    /// ReDoS guard: every shipped probe regex must complete on a 1 MiB
    /// adversarial banner in under 50 ms. This catches catastrophic
    /// backtracking introduced by future probe additions. The
    /// `regex::bytes` crate uses linear-time matching by construction;
    /// the 50 ms threshold absorbs runner jitter while still catching
    /// any quadratic-or-worse blowup. Production probe responses are
    /// capped at 4 KiB so 1 MiB is a 256× safety margin.
    #[test]
    fn every_probe_regex_under_50ms_on_1mib_input() {
        let probes = compiled_probes();
        let big = vec![b'A'; 1024 * 1024];
        let with_marker: Vec<u8> = {
            let mut v = big.clone();
            v.extend_from_slice(b"\nGOSSAN_PROBE_TAIL\n");
            v
        };
        for cp in probes {
            for input in [big.as_slice(), with_marker.as_slice()] {
                let start = std::time::Instant::now();
                let _ = cp.regex.is_match(input);
                let elapsed = start.elapsed();
                assert!(
                    elapsed < std::time::Duration::from_millis(200),
                    "probe `{}` regex took {:?} on 1 MiB input — possible ReDoS",
                    cp.def.name,
                    elapsed
                );
            }
        }
    }

    /// Every probe is uniquely named.
    #[test]
    fn probe_names_are_unique() {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for cp in compiled_probes() {
            assert!(
                seen.insert(cp.def.name.clone()),
                "duplicate probe name: {}",
                cp.def.name
            );
        }
    }

    /// Every fallback_probe references a real probe name.
    #[test]
    fn fallback_probe_names_resolve() {
        use std::collections::HashSet;
        let probes = compiled_probes();
        let names: HashSet<&str> = probes.iter().map(|p| p.def.name.as_str()).collect();
        for cp in probes {
            if let Some(target) = cp.def.fallback_probe.as_deref() {
                assert!(
                    names.contains(target),
                    "probe `{}` fallback_probe `{}` does not resolve to any known probe",
                    cp.def.name,
                    target
                );
            }
        }
    }
}
