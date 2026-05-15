# gossan-fleet

Distributed master/worker orchestration for Gossan scans.

A master node accepts a scan request, splits the target list across
worker nodes via gRPC, collects findings, and emits the merged result.

## Components

- `master::run_master` — listens on a configurable address, accepts
  worker registrations, distributes work, aggregates findings.
- `worker::run_worker` — connects to a master, pulls work, runs the
  configured scanner pipeline, streams findings/updates back.

## Usage

```rust,ignore
// Master
gossan_fleet::master::run_master("0.0.0.0:50051", &config).await?;

// Worker
gossan_fleet::worker::run_worker("http://master.internal:50051", &config).await?;
```

## License

MIT
