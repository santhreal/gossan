# Community OAuth authorization-endpoint probe-path packs (Tier-B drop-in)

Baseline OAuth authorization-endpoint locations (probed for
redirect_uri bypass) ship compiled-in
(`../../oauth_auth_endpoint_paths.txt`). Drop additional `*.txt`
files here (or under `$GOSSAN_RULES_DIR/hidden-oauth-authorize/`, or
`rules/hidden-oauth-authorize/` next to the binary)  -  one URL path
per line, `#` comments/blanks ignored, loaded verbatim. Packs extend
the baseline; only `*.txt` read (this README ignored).
