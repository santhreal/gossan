# Community dangerous-HTTP-method probe-path packs (Tier-B drop-in)

Baseline paths to test for TRACE/PUT/DELETE ship compiled-in
(`../../methods_probe_paths.txt`). The verbs themselves are RFC-fixed
in code; only the *paths to probe* are community knowledge. Drop
additional `*.txt` files here (or under
`$GOSSAN_RULES_DIR/hidden-methods/`, or `rules/hidden-methods/` next
to the binary)  -  one URL path per line, `#` comments/blanks ignored,
loaded verbatim. Packs extend the baseline; only `*.txt` read.
