# Community dangerous-CSP-value packs (Tier-B drop-in)

Baseline dangerous `script-src` values (`'unsafe-inline'`,
`'unsafe-eval'`, `data:`) and their advisories ship compiled-in
(`../../csp_script_values.toml`). New CSP-weakening tokens appear as
the spec evolves; this is the moat. Drop additional `*.toml` files
here (or under `$GOSSAN_RULES_DIR/hidden-csp/`, or `rules/hidden-csp/`
next to the binary).

A pack is a `[[rule]]` array  -  four fields, zero Rust:

```toml
[[rule]]
value = "'unsafe-hashes'"
severity = "medium"        # lowercase: info|low|medium|high|critical
title = "CSP: unsafe-hashes in script-src"
detail = "script-src allows 'unsafe-hashes'  -  event-handler attributes execute."
```

`value` is matched (lowercased) against the parsed `script-src`
list; `title`/`detail`/`severity` shape the finding. Packs **extend**
the baseline. Invalid TOML is logged and skipped, never fatal. Only
`*.toml` files are read  -  this README is ignored.
