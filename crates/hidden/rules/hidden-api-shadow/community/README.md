# Community shadow/non-prod endpoint packs (Tier-B drop-in)

Baseline shadow-API paths and their severities ship compiled-in
(`../../api_shadow_paths.toml`). Drop additional `*.toml` files here
(or under `$GOSSAN_RULES_DIR/hidden-api-shadow/`, or
`rules/hidden-api-shadow/` next to the binary).

A pack is a `[[shadow]]` array  -  three lines per entry, zero Rust:

```toml
[[shadow]]
path = "/qa"
description = "QA API endpoint"
severity = "high"          # lowercase: info | low | medium | high | critical
```

`path` is probed off the target base; `description`+`severity` shape
the finding. Packs extend the baseline. Invalid TOML is logged and
skipped, never fatal. Only `*.toml` files are read  -  this README is
ignored.
