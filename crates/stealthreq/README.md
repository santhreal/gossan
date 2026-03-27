# gossan-stealthreq

Stealth HTTP request module for gossan — user-agent rotation, jitter, and anti-detection.

## Features

- **Random User-Agent rotation** — Cycles through realistic browser UAs
- **Request jitter** — Random delays to avoid pattern detection
- **Header variation** — Per-request header differences to avoid fingerprinting
- **Configurable stealth levels** — Minimal, default, or aggressive modes

## Usage

```rust
use gossan_stealthreq::{StealthClient, StealthConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Default stealth settings
    let config = StealthConfig::default();
    let client = StealthClient::new(config)?;
    
    // Or aggressive stealth (slower, more random)
    let config = StealthConfig::aggressive();
    
    // Or minimal stealth (faster, less random)
    let config = StealthConfig::minimal();
    
    // Make a request with automatic stealth headers and jitter
    let response = client.get("https://example.com").send().await?;
    println!("Status: {}", response.status());
    
    Ok(())
}
```

## Configuration

```rust
let config = StealthConfig::default()
    .with_delay(1500)           // Base delay: 1.5s
    .with_jitter(0.3)           // ±30% jitter
    .with_proxy("http://127.0.0.1:8080")
    .with_timeout(Duration::from_secs(30));
```

## User-Agent Customization

User-Agents are loaded from `rules/user_agents.toml`. You can extend this by
adding your own TOML file with `[[user_agent]]` entries:

```toml
[[user_agent]]
string = "CustomBot/1.0"
browser = "Custom"
os = "Linux"
weight = 10
```

## License

MIT - See LICENSE file for details.
