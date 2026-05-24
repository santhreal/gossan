# Community backup-file probe packs (Tier-B drop-in)

Baseline backup/archive/dump paths and their magic-byte validators
ship compiled-in (`../../backup_files.toml`). New backup-tool
conventions appear constantly; this is the moat. Drop additional
`*.toml` files here (or under `$GOSSAN_RULES_DIR/hidden-backup/`, or
`rules/hidden-backup/` next to the binary).

A pack is a `[[check]]` array  -  zero Rust:

```toml
[[check]]
path = "/db.dump"
title = "Postgres dump exposed"
severity = "critical"          # lowercase: info|low|medium|high|critical
content_probe = "PostgreSQL"   # optional: body must contain this (anti-FP)
magic = [[80, 71, 67, 79, 80, 89]]   # optional: body must start with one of
                                     # these byte sequences (here: "PGCOPY").
                                     # tar magic (`ustar`) is matched at
                                     # offset 257 automatically.
```

`magic` is an array of byte arrays (integers 0–255)  -  exact for
non-UTF8 signatures like gzip `1f 8b`. A check with no `magic` and no
`content_probe` is soft-404-gated to avoid catch-all false positives.
Packs **extend** the baseline. Invalid TOML is logged and skipped,
never fatal. Only `*.toml` files are read  -  this README is ignored.
