# Contributing to gossan

> Part of the [Santh](https://santh.io) ecosystem.

## Quick Start
1. Fork and clone
2. `cargo test` to verify
3. Make changes
4. `cargo clippy -- -D warnings` must pass
5. `cargo test` must pass
6. Open PR

## Code Standards
- Zero `unwrap()` in non-test code
- `#![warn(clippy::pedantic)]`
- Doc comments on all public types
- Actionable error messages with Fix: guidance

## Extension Guide
To add a new capability, create a new module in the appropriate crate within `crates/` (or a new crate if it's a major feature). Register your new command or logic in the CLI layer (typically in `crates/cli/src/main.rs` or `src/main.rs`).

## License
MIT
