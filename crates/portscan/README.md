> Part of the [Santh](https://santh.io) security research ecosystem.

# gossan-portscan

[![Crates.io](https://img.shields.io/crates/v/gossan-portscan)](https://crates.io/crates/gossan-portscan)
[![Documentation](https://docs.rs/gossan-portscan/badge.svg)](https://docs.rs/gossan-portscan)
[![License](https://img.shields.io/crates/l/gossan-portscan)](LICENSE)

A fast, async TCP port scanner with TLS inspection, banner grabbing, and CVE correlation for security reconnaissance.

## Features

- **Multi-mode Port Scanning**: Choose from built-in high-risk ports, nmap top-100/1000, full range, or custom lists
- **Banner Grabbing**: Extract service versions from SSH, FTP, SMTP, HTTP, Redis, MongoDB, and more
- **TLS Certificate Inspection**: Detect expired certificates, self-signed certs, and extract Subject Alternative Names
- **Legacy TLS Detection**: Identify vulnerable TLS 1.0/1.1 protocol support (BEAST/POODLE)
- **JARM Fingerprinting**: Identify C2 frameworks (Cobalt Strike, Metasploit, Sliver) and server software via TLS fingerprinting
- **CVE Correlation**: Match banners against 20+ built-in CVE rules with CVSS scoring
- **Risky Service Detection**: Automatically flag high-risk exposures (Docker API, Redis, MongoDB, Kubernetes, Ethereum nodes, etc.)
- **Async & Concurrent**: Built on Tokio for high-performance scanning
- **Proxy Support**: Route scans through SOCKS5 proxies

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
gossan-portscan = "0.1"
```

## Quick Start

```rust
use gossan_portscan::PortScanner;
use gossan_core::{Scanner, ScanInput, Config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let scanner = PortScanner::new();
    
    // Configure scan (using gossan-core types)
    let config = Config::default();
    let input = ScanInput {
        targets: vec![/* ... */],
        metadata: Default::default(),
    };
    
    // Run scan
    let output = scanner.run(input, &config).await?;
    
    for finding in &output.findings {
        println!("{}: {}", finding.severity, finding.title);
    }
    
    Ok(())
}
```

## Standalone Usage

### Banner Grabbing

```rust
use gossan_portscan::grab_banner;
use std::time::Duration;
use tokio::net::TcpStream;

async fn grab_service_banner() {
    if let Ok(stream) = TcpStream::connect("example.com:22").await {
        if let Some(banner) = grab_banner(stream, Duration::from_secs(5)).await {
            println!("SSH banner: {}", banner);
        }
    }
}
```

### TLS Certificate Inspection

```rust
use gossan_portscan::tls::{probe_tls, days_until_expiry};
use std::time::Duration;

async fn check_cert() {
    if let Some(info) = probe_tls("example.com", 443, Duration::from_secs(10), None).await {
        println!("Subject: {}", info.subject);
        println!("Self-signed: {}", info.is_self_signed);
        
        let days = days_until_expiry(info.not_after_unix);
        if days < 0 {
            println!("Certificate expired {} days ago!", -days);
        } else {
            println!("Certificate expires in {} days", days);
        }
    }
}
```

### JARM TLS Fingerprinting

```rust
use gossan_portscan::jarm::{fingerprint, identify};
use std::time::Duration;

async fn fingerprint_tls() {
    let fp = fingerprint("example.com", 443, Duration::from_secs(10), None).await;
    
    if let Some(fp) = fp {
        println!("JARM fingerprint: {}", fp);
        
        // Check against known signatures
        if let Some(framework) = identify(&fp) {
            println!("Detected: {}", framework);
        }
    }
}
```

### CVE Correlation

```rust
use gossan_portscan::cve::{correlate, all_rules};
use gossan_core::{ServiceTarget, HostTarget, Protocol};
use std::net::IpAddr;

fn check_cves() {
    let svc = ServiceTarget {
        host: HostTarget {
            ip: IpAddr::from([127, 0, 0, 1]),
            domain: Some("target.example.com".into()),
        },
        port: 80,
        protocol: Protocol::Tcp,
        banner: None,
        tls: false,
    };
    
    // Check against built-in rules
    let findings = correlate("Server: Apache/2.4.49", &svc);
    for finding in findings {
        println!("{}: {}", finding.severity, finding.title);
    }
    
    // Load community rules from directory
    let all = all_rules(Some(std::path::Path::new("./rules/cve")));
}
```

## Port Lists

Available port collections via `gossan_core::PortMode`:

| Mode | Description |
|------|-------------|
| `PortMode::Default` | 52 high-risk service ports (Docker, Redis, MongoDB, etc.) |
| `PortMode::Top100` | nmap's top 100 TCP ports by scan frequency |
| `PortMode::Top1000` | nmap's top 1000 TCP ports |
| `PortMode::Full` | All 65535 TCP ports (1-65535) |
| `PortMode::Custom(Vec<u16>)` | User-defined port list |

Direct access to port lists:

```rust
use gossan_portscan::top_ports;

// Access nmap top ports directly
let top_100 = top_ports::TOP_100;
let top_1000 = top_ports::TOP_1000;
```

## Risky Services Detected

The scanner automatically generates findings for these high-risk exposures:

| Service | Port | Severity | Risk |
|---------|------|----------|------|
| Docker daemon (no TLS) | 2375 | Critical | Full container control, host escape |
| Docker daemon (TLS) | 2376 | High | Verify client cert requirements |
| Redis | 6379 | Critical | Often unauthenticated, RCE possible |
| MongoDB | 27017 | Critical | Often unauthenticated, full DB access |
| Elasticsearch | 9200/9300 | High | Unauthenticated data access |
| Kubernetes kubelet | 10250 | Critical | Pod exec, metadata exfiltration |
| Ethereum JSON-RPC | 8545/8546 | Critical | Wallet drain, transaction injection |
| Telnet | 23 | Critical | Plaintext protocol |
| Memcached | 11211 | Critical | DDoS amplification, data access |
| CouchDB | 5984 | High | Admin interface exposure |
| ZooKeeper | 2181 | High | Kafka cluster metadata |
| Hadoop NameNode | 50070 | High | Filesystem metadata access |
| InfluxDB | 8086 | High | Time-series data access |
| Kafka | 9092 | High | Unauthenticated message access |
| Erlang EPMD | 4369 | High | RabbitMQ/Erlang cluster attacks |

## CVE Rules

Built-in CVE detection includes:

- **OpenSSH**: CVE-2018-15473, CVE-2023-38408, CVE-2023-51767
- **Apache httpd**: CVE-2021-41773, CVE-2021-42013, CVE-2021-40438, CVE-2017-7679
- **nginx**: CVE-2021-23017
- **Microsoft IIS**: CVE-2017-7269, CVE-2010-2730
- **OpenSSL**: CVE-2022-3602 (SPOOKYSSL), CVE-2014-0160 (Heartbleed)
- **ProFTPD**: CVE-2015-3306
- **vsftpd**: CVE-2011-2523 (backdoor)
- **Exim**: CVE-2019-10149, CVE-2020-28017
- **Redis**: CVE-2022-0543 (Lua sandbox escape)
- **Elasticsearch**: CVE-2014-3120
- **MongoDB**: CVE-2013-3969

### Custom CVE Rules

Create TOML files in `rules/cve/`:

```toml
[[rule]]
pattern = "myapp/1.2.3"
cve = "CVE-2024-12345"
cvss = 9.8
severity = "critical"
description = "MyApp 1.2.3 — Remote Code Execution vulnerability."
exploit = "curl http://TARGET:8080/rce -d 'cmd=id'"
```

## JARM Fingerprints

Known signatures:

| Fingerprint | Framework/Software |
|-------------|-------------------|
| `07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1` | Cobalt Strike C2 |
| `07d19d1ad21d21d07c42d43d000000f50d155305214cf247147c43c0f1a823` | Metasploit Framework |
| `00000000000000000042d42d000000eba85c7a7a12b4a41a1a7b43614fe5b6` | Sliver C2 |
| `29d29d00029d29d21c42d43d000000032e1f2e4f19ca1bb9e16fa0c4e8b6a76` | nginx (default) |
| `2ad2ad0002ad2ad0042d42d000000e4b9f96bd97ae1b67fa98e59f073af41d` | Apache httpd 2.x |
| `27d27d27d27d27d00027d27d27d27de6d36b0c8ef5a0c870a93b84b8e90a45f` | Cloudflare |

## Architecture

This crate is designed to work both:

1. **Standalone**: Use individual modules (`tls`, `jarm`, `cve`, `top_ports`) directly
2. **As a gossan scanner**: Implement the `gossan_core::Scanner` trait for pipeline integration

The `PortScanner` implements `gossan_core::Scanner` for use in the gossan reconnaissance pipeline.

## License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.

## Contributing

Contributions are welcome! Please ensure:

1. Code follows Rust best practices and passes `cargo clippy`
2. All tests pass: `cargo test -p gossan-portscan`
3. Documentation is updated for any public API changes
4. New features include appropriate test coverage

## Security

This tool is designed for authorized security testing only. Always ensure you have permission before scanning any systems you don't own.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.
