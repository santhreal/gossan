# Changelog

All notable changes to gossan are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- Initial workspace structure with modular crate architecture.

## [0.1.0] — Initial release

- **Attack surface discovery** — Subdomains, ports, tech stack, hidden paths, cloud assets, DNS security, origin IP in one scan.
- **Subdomain enumeration** — CT logs, Wayback Machine, DNS brute forcing (`gossan-subdomain`).
- **TCP port scanning** — With TLS inspection and banner grabbing (`gossan-portscan`).
- **Technology fingerprinting** — Headers, cookies, HTML patterns (`gossan-techstack`).
- **DNS security auditing** — SPF, DMARC, DKIM, CAA, zone transfer checks (`gossan-dns`).
- **Hidden endpoint discovery** — Dirbusting, sitemap, robots.txt, swagger parsing (`gossan-hidden`).
- **Cloud asset discovery** — S3, GCS, Azure blob detection (`gossan-cloud`).
- **JavaScript analysis** — Secret detection, API endpoint extraction, WASM analysis (`gossan-js`).
- **Origin IP discovery** — CDN/WAF bypass techniques (`gossan-origin`).
- **Authenticated web crawler** — Form and parameter extraction (`gossan-crawl`).
- **Cross-module finding correlation** — Unified findings view (`gossan-correlation`).
- **Scan checkpoint and resume** — For long-running scans (`gossan-checkpoint`).
- **Raw socket SYN scanning** — Requires root privileges (`gossan-synscan`).
- **Headless browser integration** — For JavaScript-heavy targets (`gossan-headless`).
