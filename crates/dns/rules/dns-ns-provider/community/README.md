# Community DNS-provider fingerprint packs (Tier-B drop-in)

Baseline nameserver→provider fingerprints ship compiled-in
(`../../ns_providers.toml`). New managed-DNS providers appear
constantly; this is the moat. Drop additional `*.toml` files here (or
under `$GOSSAN_RULES_DIR/dns-ns-provider/`, or `rules/dns-ns-provider/`
next to the binary).

A pack is a `[[rule]]` array  -  zero Rust:

```toml
[[rule]]
match_any = ["bunny", "bunnyinfra"]   # any lowercased NS-host substring
name = "Bunny DNS"                     # display name
```

`match_any` is matched case-insensitively against each nameserver
hostname; the first rule (baseline first, then community in file order)
whose any-substring hits wins. Packs **extend** the baseline and are
appended after it  -  they never reorder or shadow a baseline rule.
Invalid TOML is logged and skipped, never fatal. Only `*.toml` files
are read  -  this README is ignored.
