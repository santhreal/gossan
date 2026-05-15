# gossan-cloud

> Part of the [Santh](https://santh.dev) security research ecosystem.

Cloud asset discovery scanner for gossan (S3, GCS, Azure Blob, DigitalOcean Spaces) — part of the Santh security research ecosystem.

Part of [gossan](https://github.com/santhsecurity/gossan).

## Usage

```rust
## Usage

```rust
use gossan_cloud::{CloudScanner, ScanInput};
use gossan_core::{Config, Target, DomainTarget, DiscoverySource};

#[tokio::main]
async fn main() {
    let scanner = CloudScanner;
    let target = Target::Domain(DomainTarget {
        domain: "example.com".into(),
        source: DiscoverySource::Seed,
    });
    
    let input = ScanInput {
        seed: "example.com".into(),
        targets: vec![target],
        live_tx: None,
        target_tx: None,
    };
    
    let output = scanner.run(input, &Config::default()).await.unwrap();
    println!("Found {} cloud assets", output.targets.len());
}
```
```

## License

MIT
