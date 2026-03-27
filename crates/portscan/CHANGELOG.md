# Changelog

All notable changes to the `gossan-portscan` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Documentation**: Comprehensive doc comments for all public APIs
  - `PortScanner` struct with usage examples
  - `PortScanner::new()` constructor
  - `PortScanner::finding_builder()` for creating scan findings
  - `grab_banner()` async function for service banner extraction
  - `TlsCertInfo` with detailed field documentation
  - `LegacyTlsResult` for TLS version probing results
  - `probe_tls()` for TLS certificate extraction
  - `probe_legacy()` for deprecated TLS version detection
  - `days_until_expiry()` for certificate expiry calculation
  - `fingerprint()` and `identify()` in JARM module
  - `CveRule` struct with TOML deserialization support
  - CVE correlation functions with examples
  - Port list constants with usage context

- **Display Implementations**: Human-readable formatting for key types
  - `Display` for `PortScanner`
  - `Display` for `TlsCertInfo`
  - `Display` for `LegacyTlsResult`
  - `Display` for `CveRule`
  - `Display` for `Jarm` fingerprint type

- **Error Handling Improvements**: Added actionable error context
  - Debug logging for banner read failures with specific error details
  - Timeout-specific logging in `grab_banner()`
  - Empty banner detection with descriptive messages

- **Edge Case Tests**: Comprehensive test coverage for boundary conditions
  - Port 0 handling (system-assigned dynamic port edge case)
  - Port 65535 (maximum valid port / `u16::MAX`)
  - Connection timeout behavior verification
  - Banner grab timeout on silent servers
  - Empty port list handling
  - Full port range (1-65535) generation
  - Large banner data handling (>512 bytes)
  - Binary/non-UTF8 data sanitization
  - Finding builder with empty/unicode/long inputs
  - CVE correlation edge cases (case insensitivity, long banners)
  - TLS info display formatting

- **Module Visibility**: Changed submodules to `pub` for standalone usage
  - `pub mod cve`
  - `pub mod jarm`
  - `pub mod tls`
  - `pub mod top_ports`

### Changed

- `PortScanner::finding_builder()` visibility changed from `pub(crate)` to `pub` for external use
- Improved `grab_banner()` to provide actionable debug logging on failures
- All port list constants now include detailed documentation

## [0.1.0] - 2024-XX-XX

### Added

- Initial release of `gossan-portscan`
- TCP connect scanner with configurable port ranges:
  - Built-in 52-port high-risk service list
  - nmap top-100 ports
  - nmap top-1000 ports
  - Full 1-65535 port range
  - Custom port lists
- Banner grabbing with protocol detection:
  - SSH version identification
  - FTP banner extraction
  - SMTP banner parsing
  - HTTP Server header detection
  - Redis unauthenticated response detection
  - MongoDB response detection
  - Telnet service detection
- TLS certificate inspection:
  - Subject and issuer extraction
  - Subject Alternative Name (SAN) enumeration
  - Certificate expiry checking (30/14 day warnings, expired detection)
  - Self-signed certificate detection
- Legacy TLS protocol detection (TLS 1.0/1.1 vulnerability checks)
- JARM TLS fingerprinting:
  - 10-probe fingerprint generation
  - Known C2 framework identification (Cobalt Strike, Metasploit, Sliver, etc.)
  - Server software fingerprinting (nginx, Apache, IIS, Cloudflare, etc.)
- CVE correlation from banners:
  - 20+ built-in rules for common services
  - CVSS scoring integration
  - Community rule loading from TOML files
  - Exploit hint generation with target substitution
- Risky service detection for 19+ high-risk exposed services:
  - Docker daemon (ports 2375, 2376)
  - Redis (port 6379)
  - MongoDB (port 27017)
  - Elasticsearch (ports 9200, 9300)
  - Kubernetes kubelet (port 10250)
  - Ethereum JSON-RPC (ports 8545, 8546)
  - And more...
- Async scanning with configurable concurrency
- SOCKS5 proxy support

[Unreleased]: https://github.com/gossan/gossan/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/gossan/gossan/releases/tag/v0.1.0
