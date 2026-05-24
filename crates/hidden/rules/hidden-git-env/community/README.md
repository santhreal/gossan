# Community git/env/secret-file exposure check packs (Tier-B drop-in)

Baseline checks (`.git/*`, `.env*`, CI/secret/config files, …; 98
entries) ship compiled-in (`../../git_env_checks.toml`). New
secret-file conventions appear constantly; this is the moat. Drop
additional `*.toml` files here (or under
`$GOSSAN_RULES_DIR/hidden-git-env/`, or `rules/hidden-git-env/` next
to the binary).

A pack is a `[[checks]]` array  -  zero Rust:

```toml
[[checks]]
path = "/.aws/credentials"
title = "AWS credentials file exposed"
severity = "critical"          # case-insensitive: info|low|medium|high|critical
detail = "/.aws/credentials leaked  -  IAM keys."
tag = "cloud-creds"
content_probe = "aws_access_key_id"   # optional: body must contain this (anti-FP)
```

Packs **extend** the baseline (drop-ins no longer replace it  -  the
old exe/CWD `data/` loader was a recall defect, now fixed). Invalid
TOML is logged and skipped, never fatal. Only `*.toml` files are read
 -  this README is ignored.
