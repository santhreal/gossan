# Community API-version probe-path packs (Tier-B drop-in)

Baseline API version prefixes (older = likelier vulnerable) ship
compiled-in (`../../api_version_paths.txt`). Drop additional `*.txt`
files here (or under `$GOSSAN_RULES_DIR/hidden-api-versions/`, or
`rules/hidden-api-versions/` next to the binary)  -  one URL path per
line, `#` comments/blanks ignored, loaded verbatim. Packs extend the
baseline; dups de-duplicated; only `*.txt` read (this README ignored).
