# Gossan Performance

## Test rig

The numbers in this file are measured on:

- CPU: AMD Ryzen 9 5950X (16C/32T, 4.9 GHz boost)
- RAM: 64 GB DDR4-3600
- NIC: counting-stub backend (no kernel / NIC) for the
  scheduler+stamper micro-bench; loopback `lo` for the banner-grab
  test
- OS: Linux 6.17, mitigations off
- Storage: WD SN850X NVMe (Gen4)
- Toolchain: rustc 1.95 stable, `--release`

The counting-stub backend (`crates/engine/benches/tx_hot_loop.rs`
and `crates/engine/tests/perf_gate.rs`) is what the perf gates use.
That backend strips out the syscall ring and NIC driver so the
measured number is gossan's own throughput ceiling — the part that
catches regressions in the schedule + packet stamp + rate-limiter
path.

For real-NIC throughput, see `docs/comparison.md` for the
per-Mbps-of-NIC numbers and `crates/engine/scripts/vs_masscan.sh`
for a head-to-head against masscan.

## Measured baselines

These are the F-section regression gates from `GOSSAN_LEGENDARY.md`.
Each is a release-only Rust integration test — CI fails when any
drops below the documented gate.

| Stage                          | Test                                                        | Gate          | Measured       |
|--------------------------------|-------------------------------------------------------------|---------------|----------------|
| Engine TX, 1 thread            | `engine/tests/perf_gate.rs::engine_tx_hot_loop_1_thread_meets_gate` | ≥5 Mpps    | 17.5 Mpps     |
| Engine TX, 4 threads           | `engine/tests/perf_gate.rs::engine_tx_hot_loop_4_threads_scales`    | ≥15 Mpps   | 66 Mpps       |
| Subdomain dedup                | `subdomain/tests/perf_gate.rs::subdomain_dedup_100k_under_1s`       | ≥1M domains/sec | 6.8M/sec  |
| Banner grab on loopback        | `portscan/tests/perf_gate_banner.rs::banner_grab_1k_loopback_under_10s` | ≥500 conn/sec | 928/sec |
| Classify                       | `classify/tests/perf_gate.rs::classify_sustains_100k_banners_per_sec_single_thread` | ≥100k/sec | 100k+/sec |
| Graph insert (10k nodes)       | `graph/tests/perf_gate.rs::graph_insert_10k_nodes_under_1s`         | <1s        | 40ms         |
| Intel query (1M-record DB)     | `intel/tests/perf_gate.rs::intel_query_by_ip_under_10ms_on_1m_records` | <10ms median | 7.1µs |

## Reproducing

```
# All seven gates at once
cargo test --workspace --release --tests perf_gate -- --nocapture

# A single gate
cargo test -p gossan-engine --release --test perf_gate -- --nocapture
```

The `--nocapture` flag is what surfaces the eprintln! lines
showing the actual measured throughput.

## Real-NIC scan

For a real bench against the network stack:

```
sudo ./crates/engine/scripts/vs_masscan.sh 10.0.0.0/16
```

Defaults: 1M pps, ports 1-65535, interface `lo`. See the script
header for environment overrides.
