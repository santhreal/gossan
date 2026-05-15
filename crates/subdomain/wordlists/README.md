# gossan-subdomain wordlists

Tiered subdomain wordlists for the bruteforce arm of
`gossan-subdomain`. Each tier is a newline-separated list of
hostname labels, one per line, no comments, no blank lines, no
leading dot.

## Tiers

| File | Lines | Description |
|------|-------|-------------|
| `top-100.txt`   | 103 | The 100ish highest-yield labels — covers ~80% of recon hits across the public CT corpus. Default for `--brute fast`. |
| `top-1k.txt`    | 491 | Production default. The full curated list previously embedded at `src/wordlist.txt`. |

A `top-10k.txt` and `full.txt` (the SecLists `subdomains-top1million-110000.txt`)
are tracked under B6 in `GOSSAN_LEGENDARY.md` and intended to ship
via a separate distribution mechanism — they're MB-class and would
bloat the published crate.

## Loader

`gossan_subdomain::brute::load_wordlist(path)` reads any of these
files into a `Vec<String>`. Skip lines starting with `#` and blank
lines so contributors can drop in their own annotated lists.

## Contributing

Drop your additions into a new file (`my-corp.txt`) and submit a PR
— the loader picks up anything in the directory passed via
`--wordlist <path>`. Keep entries:

- Lowercase, ASCII-only (use punycode for IDN — `xn--bcher-kva`).
- Without leading dot.
- Without trailing dot.
- Without protocol / port / path.
- One label per line.
