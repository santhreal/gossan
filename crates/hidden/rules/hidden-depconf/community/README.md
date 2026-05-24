# Community dependency-manifest packs (Tier-B drop-in)

Baseline dependency-manifest locations (package.json, composer.json,
go.mod, Cargo.toml, …) and their confirm-strings ship compiled-in
(`../../dependency_manifests.toml`). New ecosystems add new manifest
files every year; this is the moat. Drop additional `*.toml` files
here (or under `$GOSSAN_RULES_DIR/hidden-depconf/`, or
`rules/hidden-depconf/` next to the binary).

A pack is a `[[manifest]]` array  -  three fields, zero Rust:

```toml
[[manifest]]
path = "/pubspec.yaml"
title = "Dart pubspec.yaml exposed"
confirms = ["dependencies:", "sdk:"]   # body must contain one (anti-FP); [] = heuristic
```

Packs **extend** the baseline. Invalid TOML is logged and skipped,
never fatal. Only `*.toml` files are read  -  this README is ignored.
