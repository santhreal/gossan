# gossan-horizontal

Horizontal discovery — ASN/BGP prefix mapping and sibling-domain
correlation.

Expands the attack surface beyond the seed domain by mapping the
organization's network footprint via public BGP/WHOIS data and by
fingerprinting candidate domains for shared infrastructure (TLS
certificate issuer overlap, favicon hash collision, response body
similarity, leaked tracker IDs, internal-IP disclosure, security-header
twins, etc.).

## Conservative mode

Set `Config::conservative = true` (or pass `--conservative` from the
CLI) to enable the zero-false-positive validator that confirms whether
a candidate domain truly belongs to the same organization before
emitting it downstream.

## License

MIT
