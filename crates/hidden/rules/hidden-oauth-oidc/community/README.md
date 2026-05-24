# Community OIDC-discovery probe-path packs (Tier-B drop-in)

Baseline OIDC/OAuth `.well-known` discovery locations ship
compiled-in (`../../oauth_oidc_discovery_paths.txt`). Drop additional
`*.txt` files here (or under `$GOSSAN_RULES_DIR/hidden-oauth-oidc/`,
or `rules/hidden-oauth-oidc/` next to the binary)  -  one URL path per
line, `#` comments/blanks ignored, loaded verbatim. Packs extend the
baseline; dups de-duplicated; only `*.txt` read (this README ignored).
