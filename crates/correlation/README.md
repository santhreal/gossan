# gossan-correlation

> Part of the [Santh](https://santh.dev) security research ecosystem.

Cross-module finding correlation engine for gossan (attack chain detection) — part of the Santh security research ecosystem.

Part of [gossan](https://github.com/santhsecurity/gossan).

## Usage

```rust
## Usage

```rust
use gossan_correlation::CorrelationEngine;

let engine = CorrelationEngine::new();
let chains = engine.correlate(&all_findings);
```
```

## License

MIT
