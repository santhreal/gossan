# Community OpenAPI/Swagger probe-path packs (Tier-B drop-in)

Gossan ships a compiled-in baseline of OpenAPI/Swagger/Actuator spec
locations (`../../swagger_paths.txt`, the recall floor  -  works with
zero filesystem dependency). feroxbuster/ffuf/kiterunner ship no
curated spec catalogue; this is the moat. Drop additional `*.txt`
files here (or under `$GOSSAN_RULES_DIR/hidden-swagger/`, or next to
the installed binary in `rules/hidden-swagger/`) and the swagger
probe tries the baseline ∪ your paths.

One URL path per line, `#` comments and blanks ignored, loaded
verbatim (paths are case- and slash-significant). Example  -  add a
vendor's non-standard spec location:

```
# ACME API gateway
/internal/_spec/openapi.json
/__vendor__/swagger
```

Packs **extend** the baseline (a small vendor pack must not delete
the shipped catalogue). Duplicates are de-duplicated automatically.
Only `*.txt` files are read  -  this README is ignored.
