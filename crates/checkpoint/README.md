# gossan-checkpoint

> Part of the [Santh](https://santh.dev) security research ecosystem.

Scan checkpoint and resume for gossan — persists stage results to SQLite — part of the Santh security research ecosystem.

Part of [gossan](https://github.com/santhsecurity/gossan).

## Usage

```rust
## Usage

```rust
use gossan_checkpoint::CheckpointStore;

let store = CheckpointStore::open("gossan.db").unwrap();
let scan_id = store.new_scan("example.com", "{}").unwrap();
store.save_stage(scan_id, "dns", &targets, &findings).unwrap();
```
```

## License

MIT
