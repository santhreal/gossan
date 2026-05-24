# Community 403-bypass header packs (Tier-B drop-in)

Baseline header-injection bypass payloads ship compiled-in
(`../../bypass403_headers.toml`). New proxy/WAF header quirks are
published constantly; this is the moat. Drop additional `*.toml`
files here (or under `$GOSSAN_RULES_DIR/hidden-403-headers/`, or
`rules/hidden-403-headers/` next to the binary).

A pack is a `[[bypass]]` array  -  three lines per payload, zero Rust:

```toml
[[bypass]]
header = "X-ProxyUser-Ip"
value = "127.0.0.1"
label = "x-proxyuser-ip spoof"
```

`header`/`value` are sent on the request to the blocked path;
`label` names the technique in the finding. Packs extend the
baseline. Invalid TOML is logged and skipped, never fatal. Only
`*.toml` files are read  -  this README is ignored.
