# gossan-intel

Global passive intel for Gossan — pulls IP / domain enrichment from
local bulk datasets and configured external sources without ever
sending packets to the target.

## Sources

- **Censys** (search.censys.io)
- **Shodan**
- **Passive DNS** (CIRCL / DNSDB / PassiveTotal-shaped endpoint)
- **GreyNoise**
- **VirusTotal**
- **Local bulk SQLite index** for offline lookups

Each source is a `dyn IntelSource` and is registered in
`IntelScanner::from_config` based on which API keys / endpoints are
present in `Config`. Missing keys are logged at INFO and the source is
skipped — no scan failure.

## Output

Findings are emitted with `kind = InfoDisclosure` and tagged `intel`
plus the source name (`intel`, `censys`, `shodan`, etc.) so downstream
correlation can dedupe across providers.

## License

MIT
