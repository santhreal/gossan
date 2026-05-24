# Community service-classification packs (Tier-B drop-in)

Gossan ships a compiled-in baseline of ~128 service fingerprints
(`../builtin.toml`, the recall floor  -  works with zero filesystem
dependency). This directory is the **community moat**: drop additional
`*.toml` packs here (or under `$GOSSAN_RULES_DIR/classify/`, or next to
the installed binary in `rules/classify/`) and they are unioned on top
of the baseline at load time. Clones can copy the 128 baseline rules;
they cannot copy a continuously-contributed fingerprint catalogue.

A pack is a `[[rule]]` array. To add a service, append five lines of
TOML  -  zero Rust:

```toml
[[rule]]
id = "myproduct-http"          # globally unique
service = "MyProduct"
protocol = "tcp"               # tcp | udp
common_ports = [8080, 8443]    # hint, not a filter
patterns = ["Server: MyProduct", "X-MyProduct:"]   # any match fires
version_pattern = "MyProduct/(\\d+\\.\\d+)"          # optional; group 1 = version
security_signals = ["server-version-disclosure"]    # optional
priority = 10                  # higher wins when several rules match
```

Rules **extend** the baseline; they never delete it. Re-declaring a
baseline `id` lets a higher-`priority` pack override that service.
Invalid TOML is logged and skipped, never fatal. Only `*.toml` files
are read  -  this README is ignored.
