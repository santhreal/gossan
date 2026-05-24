# Community GraphQL endpoint probe-path packs (Tier-B drop-in)

Baseline GraphQL endpoint locations ship compiled-in
(`../../graphql_paths.txt`). Drop additional `*.txt` files here (or
under `$GOSSAN_RULES_DIR/hidden-graphql/`, or `rules/hidden-graphql/`
next to the binary)  -  one URL path per line, `#` comments/blanks
ignored, loaded verbatim. Packs extend the baseline; dups
de-duplicated; only `*.txt` read (this README ignored).
