//! Configuration-driven port lists and risky service definitions.
//!
//! This module provides TOML-based configuration for:
//! - Default port lists (default, top_100, top_1000)
//! - Risky service definitions (high-risk exposed services)
//!
//! # Default Configuration
//!
//! Built-in defaults are embedded in the binary. Users can extend these by
//! placing custom TOML files in a `rules/` directory alongside the binary.
//!
//! # Custom Extension
//!
//! Create a file like `rules/top_ports_custom.toml`:
//!
//! ```toml
//! [[ports]]
//! list = "custom"
//! ports = [8080, 8443, 3000]
//! ```
//!
//! Or extend risky services with `rules/risky_services_custom.toml`:
//!
//! ```toml
//! [[service]]
//! port = 1337
//! name = "Custom admin panel"
//! severity = "high"
//! detail = "Exposed administrative interface."
//! ```

use secfinding::Severity;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

/// A port list definition from TOML.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct PortList {
    /// List identifier: "default", "top_100", "top_1000", or custom
    pub list: String,
    /// Port numbers in this list
    pub ports: Vec<u16>,
}

/// A risky service definition from TOML.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RiskyService {
    /// Port number for this service
    pub port: u16,
    /// Human-readable service name
    pub name: String,
    /// Severity level (info, low, medium, high, critical)
    #[serde(deserialize_with = "deserialize_severity")]
    pub severity: Severity,
    /// Detailed explanation of the risk
    pub detail: String,
}

/// TOML file containing one or more port lists.
#[derive(Debug, Deserialize)]
struct PortListsFile {
    ports: Vec<PortList>,
}

/// TOML file containing one or more risky service definitions.
#[derive(Debug, Deserialize)]
struct RiskyServicesFile {
    service: Vec<RiskyService>,
}

fn deserialize_severity<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Severity, D::Error> {
    let s = String::deserialize(d)?;
    match s.to_ascii_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        other => Err(serde::de::Error::custom(format!(
            "unknown severity: {other}"
        ))),
    }
}

/// Built-in top_ports.toml content (embedded at compile time).
const BUILTIN_TOP_PORTS: &str = include_str!("../rules/top_ports.toml");

/// Built-in risky_services.toml content (embedded at compile time).
const BUILTIN_RISKY_SERVICES: &str = include_str!("../rules/risky_services.toml");

/// Global cache for built-in port lists.
static PORT_LISTS: OnceLock<HashMap<String, Vec<u16>>> = OnceLock::new();

/// Global cache for built-in risky services.
static RISKY_SERVICES: OnceLock<Vec<RiskyService>> = OnceLock::new();

/// Parse port lists from TOML content.
fn parse_port_lists(content: &str) -> Result<Vec<PortList>, toml::de::Error> {
    toml::from_str::<PortListsFile>(content).map(|f| f.ports)
}

/// Parse risky services from TOML content.
fn parse_risky_services(content: &str) -> Result<Vec<RiskyService>, toml::de::Error> {
    toml::from_str::<RiskyServicesFile>(content).map(|f| f.service)
}

/// Initialize and return the built-in port lists.
///
/// This is called lazily on first access. The result is cached for subsequent calls.
fn builtin_port_lists() -> &'static HashMap<String, Vec<u16>> {
    PORT_LISTS.get_or_init(|| {
        let mut map = HashMap::new();
        match parse_port_lists(BUILTIN_TOP_PORTS) {
            Ok(lists) => {
                for list in lists {
                    map.insert(list.list, list.ports);
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to parse built-in top_ports.toml");
            }
        }
        map
    })
}

/// Initialize and return the built-in risky services.
///
/// This is called lazily on first access. The result is cached for subsequent calls.
fn builtin_risky_services() -> &'static Vec<RiskyService> {
    RISKY_SERVICES.get_or_init(|| {
        match parse_risky_services(BUILTIN_RISKY_SERVICES) {
            Ok(services) => services,
            Err(e) => {
                tracing::error!(error = %e, "failed to parse built-in risky_services.toml");
                Vec::new()
            }
        }
    })
}

/// Get the default port list (52 high-risk ports).
///
/// # Returns
///
/// Returns a slice of the 52 built-in default ports. If parsing fails,
/// returns an empty slice (should never happen with embedded defaults).
pub fn default_ports() -> &'static [u16] {
    builtin_port_lists()
        .get("default")
        .map(|v| v.as_slice())
        .unwrap_or(&[])
}

/// Get the top 100 ports list.
///
/// # Returns
///
/// Returns a slice of the 100 most common ports by scan frequency.
/// Falls back to an empty slice if the list is unavailable.
pub fn top_100() -> &'static [u16] {
    builtin_port_lists()
        .get("top_100")
        .map(|v| v.as_slice())
        .unwrap_or(&[])
}

/// Get the top 1000 ports list.
///
/// # Returns
///
/// Returns a slice of the 1000 most common ports by scan frequency.
/// Falls back to an empty slice if the list is unavailable.
pub fn top_1000() -> &'static [u16] {
    builtin_port_lists()
        .get("top_1000")
        .map(|v| v.as_slice())
        .unwrap_or(&[])
}

/// Get the built-in risky services list.
///
/// # Returns
///
/// Returns a slice of all built-in risky service definitions.
pub fn risky_services() -> &'static [RiskyService] {
    builtin_risky_services()
}

/// Load community port lists from a directory of `*.toml` files.
///
/// Each file must contain `[[ports]]` entries. Invalid files are logged and
/// skipped — a single malformed community file must not crash the scan.
///
/// # Arguments
///
/// * `dir` - Path to directory containing `*.toml` rule files
///
/// # Returns
///
/// Returns a map of list name to port vector. Missing directories result in
/// an empty map rather than an error.
///
/// # Example
///
/// ```rust,no_run
/// use gossan_portscan::rules::load_community_port_lists;
/// use std::path::Path;
///
/// let lists = load_community_port_lists(Path::new("./rules"));
/// println!("Loaded {} custom port lists", lists.len());
/// ```
pub fn load_community_port_lists(dir: &std::path::Path) -> HashMap<String, Vec<u16>> {
    let mut lists = HashMap::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return lists, // directory missing is fine
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        // Skip built-in files to avoid double-loading
        let filename = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if filename == "top_ports" || filename == "risky_services" {
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(content) => match parse_port_lists(&content) {
                Ok(file_lists) => {
                    let count = file_lists.len();
                    for list in file_lists {
                        lists.insert(list.list, list.ports);
                    }
                    tracing::info!(path = %path.display(), lists = count, "loaded community port lists");
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), err = %e, "skipping malformed port lists file")
                }
            },
            Err(e) => {
                tracing::warn!(path = %path.display(), err = %e, "failed to read port lists file")
            }
        }
    }
    lists
}

/// Load community risky services from a directory of `*.toml` files.
///
/// Each file must contain `[[service]]` entries. Invalid files are logged and
/// skipped — a single malformed community file must not crash the scan.
///
/// # Arguments
///
/// * `dir` - Path to directory containing `*.toml` rule files
///
/// # Returns
///
/// Returns a vector of `RiskyService`s. Missing directories result in
/// an empty vector rather than an error.
///
/// # Example
///
/// ```rust,no_run
/// use gossan_portscan::rules::load_community_risky_services;
/// use std::path::Path;
///
/// let services = load_community_risky_services(Path::new("./rules"));
/// println!("Loaded {} custom risky services", services.len());
/// ```
pub fn load_community_risky_services(dir: &std::path::Path) -> Vec<RiskyService> {
    let mut services = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return services, // directory missing is fine
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        // Skip built-in files to avoid double-loading
        let filename = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if filename == "top_ports" || filename == "risky_services" {
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(content) => match parse_risky_services(&content) {
                Ok(file_services) => {
                    let count = file_services.len();
                    services.extend(file_services);
                    tracing::info!(path = %path.display(), services = count, "loaded community risky services");
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), err = %e, "skipping malformed risky services file")
                }
            },
            Err(e) => {
                tracing::warn!(path = %path.display(), err = %e, "failed to read risky services file")
            }
        }
    }
    services
}

/// Load all port lists: built-in defaults + any community TOML files.
///
/// Combines the built-in lists with any community lists found in the
/// specified directory. Community lists can extend or override built-ins.
///
/// # Arguments
///
/// * `community_dir` - Optional path to directory containing `*.toml` rule files
///
/// # Returns
///
/// Returns a map containing all available port lists.
///
/// # Example
///
/// ```rust,no_run
/// use gossan_portscan::rules::all_port_lists;
/// use std::path::Path;
///
/// // Load only built-in lists
/// let builtin_only = all_port_lists(None);
///
/// // Load built-in + community lists
/// let with_community = all_port_lists(Some(Path::new("./rules")));
/// ```
pub fn all_port_lists(community_dir: Option<&std::path::Path>) -> HashMap<String, Vec<u16>> {
    let mut lists: HashMap<String, Vec<u16>> = builtin_port_lists().clone();
    if let Some(dir) = community_dir {
        let community = load_community_port_lists(dir);
        lists.extend(community);
    }
    lists
}

/// Load all risky services: built-in defaults + any community TOML files.
///
/// Combines the built-in services with any community services found in the
/// specified directory.
///
/// # Arguments
///
/// * `community_dir` - Optional path to directory containing `*.toml` rule files
///
/// # Returns
///
/// Returns a vector containing all available risky services.
///
/// # Example
///
/// ```rust,no_run
/// use gossan_portscan::rules::all_risky_services;
/// use std::path::Path;
///
/// // Load only built-in services
/// let builtin_only = all_risky_services(None);
///
/// // Load built-in + community services
/// let with_community = all_risky_services(Some(Path::new("./rules")));
/// ```
pub fn all_risky_services(community_dir: Option<&std::path::Path>) -> Vec<RiskyService> {
    let mut services = builtin_risky_services().clone();
    if let Some(dir) = community_dir {
        let community = load_community_risky_services(dir);
        services.extend(community);
    }
    services
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_default_ports_are_nonempty() {
        let ports = default_ports();
        assert!(!ports.is_empty(), "default ports should not be empty");
        assert!(ports.contains(&80), "default should include port 80");
        assert!(ports.contains(&443), "default should include port 443");
        assert!(ports.contains(&22), "default should include SSH");
    }

    #[test]
    fn builtin_top_100_has_100_ports() {
        let ports = top_100();
        assert_eq!(ports.len(), 100, "top_100 should have exactly 100 ports");
    }

    #[test]
    fn builtin_top_1000_has_approx_1000_ports() {
        let ports = top_1000();
        // nmap's "top 1000" is approximate - actual count varies by source
        assert!(
            ports.len() >= 950,
            "top_1000 should have approximately 1000 ports (got {})",
            ports.len()
        );
    }

    #[test]
    fn builtin_risky_services_are_nonempty() {
        let services = risky_services();
        assert!(!services.is_empty(), "risky services should not be empty");
        // Check for some known risky ports
        assert!(
            services.iter().any(|s| s.port == 2375),
            "should include Docker port"
        );
        assert!(
            services.iter().any(|s| s.port == 6379),
            "should include Redis port"
        );
    }

    #[test]
    fn risky_services_have_required_fields() {
        for svc in risky_services() {
            assert!(!svc.name.is_empty(), "service name should not be empty");
            assert!(!svc.detail.is_empty(), "service detail should not be empty");
            assert!(svc.port > 0, "port should be > 0");
        }
    }

    #[test]
    fn community_port_lists_load_from_toml() {
        let dir = std::env::temp_dir().join("gossan_port_lists_test");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("custom.toml"),
            r#"
[[ports]]
list = "custom"
ports = [8080, 8443, 3000]
"#,
        )
        .unwrap();
        let lists = load_community_port_lists(&dir);
        assert!(lists.contains_key("custom"));
        assert_eq!(lists["custom"], vec![8080, 8443, 3000]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn community_risky_services_load_from_toml() {
        let dir = std::env::temp_dir().join("gossan_risky_test");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("custom.toml"),
            r#"
[[service]]
port = 1337
name = "Custom admin panel"
severity = "high"
detail = "Exposed administrative interface."
"#,
        )
        .unwrap();
        let services = load_community_risky_services(&dir);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].port, 1337);
        assert_eq!(services[0].name, "Custom admin panel");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn all_port_lists_includes_community() {
        let dir = std::env::temp_dir().join("gossan_all_ports_test");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("extra.toml"),
            r#"
[[ports]]
list = "extra"
ports = [1111, 2222]
"#,
        )
        .unwrap();
        let lists = all_port_lists(Some(&dir));
        assert!(lists.contains_key("default"), "should have default");
        assert!(lists.contains_key("extra"), "should have extra");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn all_risky_services_includes_community() {
        let builtin_count = risky_services().len();
        let dir = std::env::temp_dir().join("gossan_all_risky_test");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("extra.toml"),
            r#"
[[service]]
port = 9999
name = "Test service"
severity = "medium"
detail = "Test detail."
"#,
        )
        .unwrap();
        let services = all_risky_services(Some(&dir));
        assert_eq!(services.len(), builtin_count + 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_community_file_is_skipped() {
        let dir = std::env::temp_dir().join("gossan_bad_test");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("broken.toml"), "this is not valid [[ports]]").unwrap();
        let lists = load_community_port_lists(&dir);
        assert!(lists.is_empty(), "malformed file should be skipped gracefully");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_directory_returns_empty() {
        let dir = std::path::Path::new("/nonexistent/path/that/does/not/exist");
        let lists = load_community_port_lists(dir);
        assert!(lists.is_empty());
        let services = load_community_risky_services(dir);
        assert!(services.is_empty());
    }

    #[test]
    fn parse_port_lists_works() {
        let toml = r#"
[[ports]]
list = "test"
ports = [80, 443]
"#;
        let lists = parse_port_lists(toml).unwrap();
        assert_eq!(lists.len(), 1);
        assert_eq!(lists[0].list, "test");
        assert_eq!(lists[0].ports, vec![80, 443]);
    }

    #[test]
    fn parse_risky_services_works() {
        let toml = r#"
[[service]]
port = 8080
name = "Test"
severity = "high"
detail = "Test detail."
"#;
        let services = parse_risky_services(toml).unwrap();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].port, 8080);
        assert_eq!(services[0].severity, Severity::High);
    }
}
