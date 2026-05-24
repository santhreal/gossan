# Community error/debug-disclosure packs (Tier-B drop-in)

Baseline error-trigger payloads, stack-trace/SQL/SSTI disclosure
needles, and debug-header rules ship compiled-in
(`../../error_disclosure.toml`). The needle set is **precision-tuned**
(generic FP-prone needles were deliberately removed  -  see the
`# NOTE` lines in the generated pack); drop-ins ADD, they never
remove or relax the baseline. New framework error signatures appear
constantly; this is the moat. Drop additional `*.toml` files here (or
under `$GOSSAN_RULES_DIR/hidden-error-disc/`, or
`rules/hidden-error-disc/` next to the binary).

One pack, up to three sections  -  zero Rust:

```toml
[[trigger]]                 # extra error-triggering URL suffix
suffix = "/?debug=1"
desc = "verbose-mode toggle"

[[pattern]]                 # extra disclosure needle (substring)
pattern = "panicked at 'index out of bounds"
name = "Rust panic in error response"
severity = "high"           # lowercase: info|low|medium|high|critical

[[debug_header]]            # extra production-leak header
header = "x-rack-cache"
name = "Rack cache debug"
severity = "low"
```

Keep needles HIGH-SIGNAL  -  a substring that appears in benign bodies
(e.g. `on line `, `/app/`) is a false positive on healthy sites and
must not be added. Packs **extend** the baseline. Invalid TOML is
logged and skipped, never fatal. Only `*.toml` files are read.
