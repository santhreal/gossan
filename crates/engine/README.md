# gossan-engine

High-performance stateless SYN scanner and banner grabber — the
masscan-class scan engine for the Gossan attack-surface scanner.

## Architecture

- **netforge** packet I/O (sendmmsg / pnet / AF_XDP backends)
- **Stateless cookie verification** (no per-target state in TX)
- **Multi-threaded TX** with CPU pinning, stride-partitioned Blackrock
  permutation, per-thread raw socket
- **Single shared RX** thread with `recvmmsg` batched receive
- **Slash24 RST-burst backoff**: when a /24 RSTs us above
  `RST_BURST_THRESHOLD` packets/sec the RX thread inserts the prefix
  into a 30-second backoff and TX threads silently skip probes against
  that subnet for the window. Surfaced as `backoff_skipped` in the
  scan-end log.
- **Banner grab + classify** post-SYN-ACK with 500-way concurrency,
  routed through `gossan-classify`.

## Throughput

- 17 Mpps single-thread on a 5950X
- 96–110 Mpps at 8 threads, NIC-bound thereafter
- Scales linearly with TX threads up to ~8; beyond that softirq /
  ring contention dominates and AF_XDP (separate backend) is the next
  step.

## Running

```rust,ignore
let scanner = gossan_engine::EngineScanner::new();
scanner.run(input, &config).await?;
```

CAP_NET_RAW (or root) required.

## License

MIT
