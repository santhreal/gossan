# Community JARM fingerprint packs (Tier-B drop-in)

Gossan ships a compiled-in baseline of known JARM fingerprints
(`../fingerprints.toml`, the recall floor  -  C2 frameworks plus a few
common servers for context, works with zero filesystem dependency).
This is the **moat**: nmap, masscan and RustScan ship no JARM C2
catalogue at all, and the threat-intel community publishes new C2
fingerprints continuously. Drop additional `*.toml` packs here (or
under `$GOSSAN_RULES_DIR/jarm/`, or next to the installed binary in
`rules/jarm/`) and `identify()` resolves against the baseline ∪ your
packs at load time.

A pack is a `[[fingerprint]]` array. Adding a freshly-published C2
fingerprint is two lines of TOML  -  zero Rust:

```toml
[[fingerprint]]
hash = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"
name = "Cobalt Strike C2 (4.10 profile X)"
```

`hash` is the full 62-character JARM string; `name` is the label
reported on a match. Packs **extend** the baseline (a small feed must
not delete the shipped catalogue). Invalid TOML is logged and skipped,
never fatal. Only `*.toml` files are read  -  this README is ignored.
