# Community mail-provider fingerprint packs (Tier-B drop-in)

Baseline MX→provider fingerprints ship compiled-in
(`../../mail_providers.toml`). New mail-security/SEG vendors appear
constantly; this is the moat. Drop additional `*.toml` files here (or
under `$GOSSAN_RULES_DIR/dns-mail-provider/`, or
`rules/dns-mail-provider/` next to the binary).

A pack is a `[[rule]]` array  -  zero Rust:

```toml
[[rule]]
match_any = ["protection.outlook"]    # any lowercased MX-host substring
name = "Microsoft Defender for O365"  # display name
```

`match_any` is matched case-insensitively against each MX exchange
host; the first rule (baseline first, then community in file order)
whose any-substring hits wins. Packs **extend** the baseline and are
appended after it  -  they never reorder or shadow a baseline rule.
Invalid TOML is logged and skipped, never fatal. Only `*.toml` files
are read  -  this README is ignored.
