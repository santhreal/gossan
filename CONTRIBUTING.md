# Contributing to gossan

Part of the [Santh](https://santh.dev) ecosystem.

## Quick start

1. Fork and clone.
2. `cargo test --workspace --no-fail-fast` — must be all green.
3. `cargo clippy --workspace --all-targets -- -D warnings` — must
   exit 0.
4. Make your change.
5. `cargo test` again.
6. Open a PR.

## Code standards

- Zero `.unwrap()` / `panic!()` / `todo!()` / `unimplemented!()`
  outside `#[cfg(test)]`. `.expect("documented invariant")` is fine
  when the message names the invariant the caller is relying on.
- Public types and functions get doc comments.
- Errors carry a `Fix:` line where the user can act on them.
- Lint config lives in the root `Cargo.toml [workspace.lints]`;
  per-crate `lib.rs` only sets the cross-cutting `#![cfg_attr(not
  (test), deny(...))]` for correctness lints.

## The 10-test contract

For every shipped feature / rule / probe the contract from
`GOSSAN_LEGENDARY.md` requires:

1. **Positive truth** — known-good fixtures, exact metadata
   asserted (`assert_eq!(findings.iter().filter(|f| f.rule == "X"
   && f.line == 12).count(), 1)`, never `assert!(!findings.
   is_empty())`).
2. **Negative precision** — sanitized variants must NOT fire.
3. **Adversarial / evasion** — hostile inputs; each successful
   evasion is a real finding to fix in the engine, not a test to
   weaken.
4. **Cross-file / interprocedural** where applicable.
5. **Real-world corpus / CVE replay** where applicable.
6. **Property tests** (proptest, 10k+ cases per invariant).
7. **Differential** vs competitor tools (masscan, naabu, amass,
   nuclei, nmap, semgrep …).
8. **Performance** (criterion, regression-gated; perf gates live
   in `crates/*/tests/perf_gate*.rs` and run only in `--release`).
9. **Scale** (large corpus / synthetic 30M-LOC where applicable).
10. **End-to-end CLI** drives the real binary via
    `assert_cmd::Command::cargo_bin("gossan")` and parses
    stdout/stderr.

## Adding a CVE rule

`rules/cve/community-2025.toml` is the canonical drop-in. Add a
`[[rule]]` block with:

```toml
[[rule]]
pattern = "<substring matched against the banner>"
cve = "CVE-YYYY-NNNN"
cvss = 9.8
severity = "critical"
description = "Short, specific description; reference the CVE."
exploit = "Optional curl/msfconsole one-liner. TARGET is replaced at runtime."
```

The loader is `gossan_portscan::cve::load_community_rules`; tests
in `crates/portscan/src/cve.rs` exercise the round-trip.

## Adding a service probe

`crates/portscan/rules/service_probes.toml` carries the active
probe set. Each probe is a `[[probe]]` block with the protocol
hint, the query bytes, and the regex(es) to match against the
response. Add positive + negative fixtures under
`crates/portscan/tests/probes/<probe_name>/`.

## Adding a tech-stack fingerprint

`truestack` (separate crate) holds the `[[rules]]` set in
`src/rules.toml`. Each rule names the technology, the categories,
the positive `signals` (header/cookie/body matchers), and any
`negative_signals`. gossan picks up truestack rules at runtime
through `gossan_techstack::bridge::probe`.

## Adding a WAF detector

`wafrift` (separate crate) holds the WAF detector TOMLs in
`software/wafrift/rules/detect/<vendor>.toml`. gossan-hidden picks
them up via the `wafrift-detect` workspace dep.

## Adding a secret detector

`gossan-keyhog-lite` is the vendored slice. The detector schema
mirrors upstream `keyhog-core`'s detector format (see
`software/keyhog/detectors/aws-access-key.toml` for a template).
Drop a new detector TOML into the directory keyhog-lite is
configured to load from at runtime; it's picked up via
`gossan_keyhog_lite::load_detectors(path)` with no rebuild.

## Adding a new scanner crate

1. `cargo new --lib crates/<name>`
2. Set `name = "gossan-<name>"` in the new Cargo.toml.
3. Implement `Scanner` from `gossan_core::scanner`.
4. Register the crate in the root `[workspace] members` list.
5. Wire it into `crates/cli/Cargo.toml` as an optional dep + a
   feature flag, then into `crates/cli/src/pipeline/full.rs`.
6. Hit the 10-test contract above.

## Documentation

- Every new public fn gets a doc comment with at least a `# Errors`
  section if it returns `Result`.
- Architectural changes update `docs/architecture.md`.
- Performance changes update `docs/performance.md` + the matching
  perf-gate test in `crates/*/tests/perf_gate*.rs`.
- Comparison changes (we beat / lose to a competitor on a new
  axis) update `docs/comparison.md`.

## License

MIT
