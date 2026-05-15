# gossan-classify

Banner classification and service fingerprinting for Gossan.

Takes raw TCP banner responses and classifies them into:
- Service type (HTTP, SSH, FTP, MySQL, Redis, etc.)
- Version extraction (Apache 2.4.52, OpenSSH 8.9, etc.)
- OS hints from protocol behavior
- Security posture signals (default creds, debug mode, info leaks)

## Usage

```rust
use gossan_classify::BannerClassifier;

let c = BannerClassifier::new();
let matches = c.classify("Server: nginx/1.25.3\r\n");
for m in matches {
    println!("{}: {} (confidence {:.0}%)", m.rule_id, m.service, m.confidence * 100.0);
}
```

## Extending

Built-in rules ship as Rust constants in `src/rules.rs`. Community rules
load from a TOML directory at runtime — see the per-rule contract in
`GOSSAN_LEGENDARY.md` Section B6 for the schema.

## License

MIT
