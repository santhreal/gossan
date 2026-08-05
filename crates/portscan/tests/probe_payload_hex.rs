//! Every `0x…` probe payload in service_probes.toml must be even-length hex.
//!
//! Regression: DNS_TCP_VERSION shipped an odd-length payload and was skipped
//! at runtime with "invalid hex probe payload".

#[test]
fn every_hex_probe_payload_has_even_digit_count() {
    let raw = include_str!("../rules/service_probes.toml");
    let mut failures = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("payload = \"0x") else {
            continue;
        };
        let Some(end) = rest.find('"') else {
            continue;
        };
        let hex = &rest[..end];
        if hex.is_empty() {
            continue;
        }
        if hex.len() % 2 != 0 {
            failures.push(format!("line {}: odd hex length {} ({hex})", idx + 1, hex.len()));
        }
        if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            failures.push(format!("line {}: non-hex digits in {hex}", idx + 1));
        }
    }
    assert!(
        failures.is_empty(),
        "invalid hex payloads:\n{}",
        failures.join("\n")
    );
}

#[test]
fn dns_tcp_version_payload_is_fixed() {
    let raw = include_str!("../rules/service_probes.toml");
    let mut saw = false;
    let mut payload = String::new();
    for line in raw.lines() {
        if line.contains("name = \"DNS_TCP_VERSION\"") {
            saw = true;
            continue;
        }
        if saw && line.trim().starts_with("payload =") {
            payload = line.trim().to_string();
            break;
        }
    }
    assert!(saw, "DNS_TCP_VERSION probe missing");
    assert!(
        payload.contains("0x001e0000010000010000000000000776657273696f6e0462696e640000100003"),
        "unexpected DNS_TCP_VERSION payload: {payload}"
    );
}
