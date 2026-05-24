# Community auth-endpoint probe-path packs (Tier-B drop-in)

Baseline auth endpoints probed for missing rate-limiting ship
compiled-in (`../../rate_limit_auth_paths.txt`). Drop additional
`*.txt` files here (or under `$GOSSAN_RULES_DIR/hidden-rate-limit/`,
or `rules/hidden-rate-limit/` next to the binary)  -  one URL path per
line, `#` comments/blanks ignored, loaded verbatim. Packs extend the
baseline; dups de-duplicated; only `*.txt` read (this README ignored).
