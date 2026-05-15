# Hidden directory wordlists

Tier-B community knowledge files used by `gossan-hidden::directory_brute`.

| File          | Words | Purpose |
|---------------|-------|---------|
| `top-100.txt` | 90    | Fastest pass — admin panels, top auth/config paths only. |
| `top-1k.txt`  | 446   | Standard pass — full vendored wordlist (currently a superset of `directory_wordlist.txt`). |

Both files are bare lists, one path-fragment per line. Comments
(`#…`) and blank lines are stripped at load time, but the canonical
shipped files are already cleaned.

## Adding entries

- One path per line. No leading `/` (the brute-forcer adds it).
- No duplicates within a file (`sort -u`).
- Do not include comments or blank lines in shipped files.
- After editing, run:

```sh
cargo test -p gossan-hidden directory_brute
```

A larger `top-10k.txt` and an unbounded `full.txt` are intentionally
out-of-tree — they bloat the published crate. Distribute them as a
separate download and let the user point at them via
`--directory-brute-wordlist <path>`.
