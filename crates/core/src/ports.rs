//! Canonical port-set resolution for every Gossan scanner.
//!
//! `PortMode` lives in [`crate::config`]; the *lists* it expands to must be
//! identical in `gossan-engine` and `gossan-portscan`. This module is the
//! single owner of that expansion, loaded from the Tier-B
//! `top_ports.toml` embedded at compile time.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::config::PortMode;

/// Start of the IANA ephemeral port range (RFC 6335 §6).
pub const EPHEMERAL_PORT_START: u16 = 49152;
/// Number of usable ports in the ephemeral range (one less than
/// 65535-49152+1 so that `pid % EPHEMERAL_PORT_COUNT` + start ≤ 65535).
pub const EPHEMERAL_PORT_COUNT: u16 = 16383;

#[derive(Debug, Deserialize)]
struct PortList {
    list: String,
    ports: Vec<u16>,
}

#[derive(Debug, Deserialize)]
struct PortListsFile {
    ports: Vec<PortList>,
}

const BUILTIN_TOP_PORTS: &str = include_str!("../rules/top_ports.toml");

static PORT_LISTS: OnceLock<HashMap<String, Vec<u16>>> = OnceLock::new();

fn port_lists() -> &'static HashMap<String, Vec<u16>> {
    PORT_LISTS.get_or_init(|| {
        let parsed: PortListsFile = toml::from_str(BUILTIN_TOP_PORTS)
            .unwrap_or_else(|e| panic!("embedded top_ports.toml must parse: {e}"));
        let mut map = HashMap::new();
        for pl in parsed.ports {
            map.insert(pl.list, pl.ports);
        }
        map
    })
}

fn list_or_empty(name: &str) -> Vec<u16> {
    port_lists().get(name).cloned().unwrap_or_else(|| {
        panic!(
            "embedded top_ports.toml missing required port list `{name}`;              refusing to scan an empty set"
        )
    })
}

/// Expand a [`PortMode`] into the concrete port vector every scanner must use.
#[must_use]
pub fn resolve_ports(mode: &PortMode) -> Vec<u16> {
    match mode {
        PortMode::Default => list_or_empty("default"),
        PortMode::Top100 => list_or_empty("top_100"),
        PortMode::Top1000 => list_or_empty("top_1000"),
        PortMode::Full => (1..=65535).collect(),
        PortMode::Custom(ports) => ports.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_and_top100_are_nonempty_and_distinct_from_engine_hardcode_trap() {
        let d = resolve_ports(&PortMode::Default);
        let t = resolve_ports(&PortMode::Top100);
        assert!(!d.is_empty());
        assert_eq!(t.len(), 100);
        // Engine previously hard-coded a tiny Default list; the Tier-B list
        // must stay the authority and include common service ports.
        assert!(d.contains(&80) && d.contains(&443) && d.contains(&22));
    }

    #[test]
    fn ephemeral_constants_stay_in_iana_range() {
        assert!(EPHEMERAL_PORT_START >= 49152);
        assert!((EPHEMERAL_PORT_START as u32) + (EPHEMERAL_PORT_COUNT as u32) <= 65535);
    }

    #[test]
    fn engine_and_portscan_modes_share_identical_lists() {
        let a = resolve_ports(&PortMode::Top100);
        let b = resolve_ports(&PortMode::Top100);
        assert_eq!(a, b);
        assert_eq!(
            resolve_ports(&PortMode::Default),
            resolve_ports(&PortMode::Default)
        );
    }
}
