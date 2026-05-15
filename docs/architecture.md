# Gossan Architecture

## Pipeline DAG

Gossan is a streaming pipeline: a tagged enum (`Target`) flows
through scanner stages, each consuming a variant and emitting the
next stage's input plus security findings.

```
                ┌──────────────┐
                │     Seed     │  (str → Target::Domain)
                └──────┬───────┘
                       │
   ┌───────────────────┴───────────────────┐
   │                                       │
   ▼                                       ▼
┌──────────────┐                   ┌─────────────────┐
│  subdomain   │  Domain → Domain  │   horizontal    │  Domain → Domain (siblings)
│              │                   │                 │  Domain → Network
└──────┬───────┘                   └────────┬────────┘
       │                                    │
       └──────────────┬─────────────────────┘
                      │
                      ▼
              ┌───────────────┐
              │     intel     │  Domain/Host enrichment (passive)
              └───────┬───────┘
                      │
                      ▼
              ┌────────────────┐
              │ engine/portscan│  Host → Service
              │ (port scan)    │
              └───────┬────────┘
                      │
       ┌──────────────┼──────────────┐
       ▼              ▼              ▼
   ┌────────┐  ┌────────────┐  ┌──────────┐
   │  dns   │  │ techstack  │  │  hidden  │  Web → Finding
   │        │  │            │  │          │
   └────────┘  └─────┬──────┘  └─────┬────┘
                     │               │
                     ▼               ▼
              ┌────────────┐   ┌──────────┐
              │     js     │   │  cloud   │
              │            │   │          │
              └─────┬──────┘   └──────────┘
                    │
                    ▼
              ┌────────────┐
              │   crawl    │  Web → Web (linked pages)
              └────────────┘
```

Each stage emits findings via `ScanInput::live_tx` and downstream
targets via `ScanInput::target_tx`. There is no buffering pass — a
finding emitted by `subdomain` is visible at the cli output sink
within milliseconds of detection.

## The Scanner trait

```rust
#[async_trait]
pub trait Scanner: Send + Sync {
    fn name(&self) -> &'static str;
    fn tags(&self) -> &[&'static str];
    fn accepts(&self, target: &Target) -> bool;
    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<()>;
}
```

Every scanner crate implements `Scanner` and nothing else. The
`Registry` is the orchestrator that pipes `target_tx` of stage N
into the `target_rx` of stage N+1, sized by tier (subdomain/intel
in tier 0, port scan in tier 1, web/dns/js in tier 2, cloud/scm in
tier 3).

## ScanInput streaming model

```rust
pub struct ScanInput {
    pub seed: String,
    pub target_rx: tokio::sync::Mutex<UnboundedReceiver<Target>>,
    pub live_tx: UnboundedSender<Finding>,
    pub target_tx: UnboundedSender<Target>,
    pub resolver: Arc<TokioAsyncResolver>,
}
```

- `target_rx` is the inbound stream. Drains until the channel
  closes.
- `live_tx.send(f)` emits a finding. The cli consumer prints it
  immediately (or buffers for a final report, depending on output
  format).
- `target_tx.send(t)` emits a downstream target. The next pipeline
  tier picks it up.
- `resolver` is shared (Arc) — DNS lookups inside a stage reuse the
  resolver's cache.

Backpressure: all channels are unbounded by default. Throttling is
controlled per-stage via `Config::concurrency` and the per-host
rate limiter (`gossan_core::HostRateLimiter`).

## Engine fast path

For port scanning at scale (>10k hosts), gossan registers
`gossan_engine::EngineScanner` instead of `gossan_portscan::
PortScanner` when running as root. Engine path:

1. Resolve all targets to IPv4.
2. Build a SYN packet template (fixed source IP/port).
3. **Multi-thread TX**: 8 threads, each with its own raw socket,
   stride-partitioned [Blackrock](https://github.com/robertdavidgraham/masscan/blob/master/src/rand-blackrock.h)
   permutation, CPU-pinned.
4. **Single shared RX**: `recvmmsg`-batched, verifies stateless
   cookie on each SYN-ACK, drops everything else.
5. **RST-burst CONSUMER**: per-/24 RST counts feed an
   `Slash24Backoff` table; TX threads skip subnets in active backoff.
6. **Banner grab + classify**: 500-way concurrent post-scan TCP
   connect + classifier (`gossan_classify::BannerClassifier`).

Throughput baseline: 17 Mpps single-thread, 96-110 Mpps at 8
threads (counting-stub backend; NIC-bound on real hardware).

## Vendor slice

`crates/keyhog-lite/` is the only vendored crate. It's a frozen,
CPU-only subset of upstream `keyhog-core` + `keyhog-scanner` +
`keyhog-verifier`. Used by `gossan-js`, `gossan-scm`, and
`gossan-crawl` for hardcoded-secret detection. Maintained in
parallel with the upstream schema (see
`crates/keyhog-lite/README.md`).

## Output

CLI receives `Vec<Finding>` and dispatches via
`crates/cli/src/output.rs::print_findings`:

- `text` / `json` / `jsonl` / `sarif` / `markdown` → delegated to
  `santh_output::render()`.
- `masscan-grep` → rendered locally as
  `Host: ip ()\tPorts: port/open/proto//service//`, picking up the
  `ip:` / `port:` / `service:` tags that `gossan-portscan` and
  `gossan-engine` stamp on every open-port discovery.

## Testing contract

Per `GOSSAN_LEGENDARY.md`'s doctrine, every shipped feature carries:

- Positive truth (exact location/metadata asserted)
- Negative precision (sanitized variants must not fire)
- Adversarial / evasion (each successful evasion is a real finding)
- Cross-file / interprocedural where applicable
- Real-world corpus / CVE replay where applicable
- Property tests (proptest)
- Differential vs competitor tools (masscan, naabu, amass, etc.)
- Performance (criterion, regression-gated)
- Scale (large corpus / synthetic)
- End-to-end CLI (drives the real binary, parses stdout)

The release-only perf gates in `crates/{engine,classify,subdomain,
portscan,graph,intel}/tests/perf_gate*.rs` are the regression
breakers — CI fails if any drops below its documented baseline.
