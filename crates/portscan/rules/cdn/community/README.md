# Community CDN-edge substring packs (Tier-B drop-in)

Gossan ships a compiled-in baseline of CDN-edge PTR substrings
(`../../cdn_edge_hosts.txt`, the recall floor). New CDN operators
appear every year; this is the moat. Drop additional `*.txt` files
here (or under `$GOSSAN_RULES_DIR/cdn/`, or next to the installed
binary in `rules/cdn/`) and `ptr_is_cdn()` matches the baseline ∪
your packs.

One substring per line, `#` comments and blanks ignored, matched
case-insensitively against the reverse-DNS name. Example  -  add a new
CDN:

```
# Gcore CDN
gcdn.co
# Arvancloud
arvancdn.ir
```

**Never add general cloud-hosting domains** (`amazonaws.com`,
`azure.com`, `googleusercontent.com`, bare `compute`): a target's
real origin commonly has those PTRs, so skipping them silently
refuses to scan every cloud-hosted target. Only genuine CDN-EDGE
operators. Packs **extend** the baseline; invalid lines are harmless
(a substring that never matches just does nothing). Only `*.txt`
files are read  -  this README is ignored.
