# Community debug/monitoring-endpoint packs (Tier-B drop-in)

Baseline debug/profiler/monitoring endpoints (Spring Actuator, Django
debug toolbar, Go pprof, Prometheus, …) ship compiled-in
(`../../debug_probes.toml`). Frameworks add new debug surfaces every
release; this is the moat. Drop additional `*.toml` files here (or
under `$GOSSAN_RULES_DIR/hidden-debug/`, or `rules/hidden-debug/`
next to the binary).

A pack is a `[[probe]]` array  -  five fields, zero Rust:

```toml
[[probe]]
path = "/__acme/debug"
name = "ACME Debug Console"
framework = "ACME"
severity = "critical"          # case-insensitive: info|low|medium|high|critical
confirm_strings = ["acme-debug"]   # body must contain one (anti-FP); [] = path-only
```

`confirm_strings` are required on `critical` probes (false-positive
guard, except heapdump-style paths). Packs **extend** the baseline.
Invalid TOML is logged and skipped, never fatal. Only `*.toml` files
are read  -  this README is ignored.
