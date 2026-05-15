# gossan-keyhog-lite

**Vendor slice — not for general use.** This crate is a frozen, pure-CPU
subset of [keyhog-core](https://github.com/santhsecurity/keyhog) +
keyhog-scanner + keyhog-verifier, vendored inside the Gossan workspace
so that `gossan-js`, `gossan-scm`, and `gossan-crawl` can detect
hardcoded secrets without dragging the upstream `wgpu` / `vyre` /
`vyre-driver-wgpu` GPU stack into the gossan build graph.

The cross-workspace `workspace = true` resolution of those upstream
deps is what previously kept js / scm / crawl excluded from the
workspace.

## Surface

```rust
use gossan_keyhog_lite::{
    Chunk, ChunkMetadata, CompiledScanner, DedupScope, Detector,
    Match, MatchLocation, RawMatch, Severity, VerificationEngine,
    VerificationResult, VerifyConfig, dedup_matches, load_detectors,
    redact,
};
```

This is intentionally narrower than upstream — it covers only what
gossan-js + gossan-scm + gossan-crawl import.

## Detection path

Pure-CPU AC prefilter (aho-corasick over `keywords`) + per-pattern
`regex` compile. No SIMD-Vectorscan, no GPU. Throughput on the
gossan-js JavaScript corpus is well below upstream's 50 GB/s SIMD path
but the workload here is tens of MB per scan, not hundreds of GB.

## Verification path

Stubbed: `VerificationEngine::verify_all` returns each input
`RawMatch` as `VerificationResult::Unknown`. Live verification (HTTP
probes against AWS / Stripe / etc) lives in upstream keyhog-verifier
and pulls in `tokio` + provider SDKs that we deliberately keep out of
the gossan build graph. Verification is implemented honestly — the
result is "we have no way to verify from inside gossan", not
"verified".

## Sync from upstream

Detectors live in `software/keyhog/detectors/`. This crate carries
**no** detector TOML files of its own — at runtime
`load_detectors(path)` reads whichever directory the caller points
it at (gossan-js and gossan-scm point at the keyhog detector tree;
in vendored builds the caller drops a frozen copy alongside the
binary).

When the upstream detector schema changes (new optional field,
renamed key, etc.), update `Detector` / `Pattern` / `Companion` in
`src/detector.rs` to match. The schema is small (~20 fields) so this
is minutes, not hours.
