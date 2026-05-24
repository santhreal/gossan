# Community 403-target probe-path packs (Tier-B drop-in)

Baseline WAF/auth-blocked paths (probed for 403-bypass) ship
compiled-in (`../../bypass403_sensitive_paths.txt`). Drop additional
`*.txt` files here (or under `$GOSSAN_RULES_DIR/hidden-403-paths/`,
or `rules/hidden-403-paths/` next to the binary)  -  one URL path per
line, `#` comments/blanks ignored, loaded verbatim. Packs extend the
baseline; dups de-duplicated; only `*.txt` read (this README ignored).
