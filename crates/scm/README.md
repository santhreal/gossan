# gossan-scm

Source Control Mapping for Gossan — discovers GitHub / GitLab
organizations and repositories tied to the seed domain, then mines them
for secrets and internal-package references.

## Discovery

- WHOIS / DMARC / SPF parsing for `git*` references
- GitHub org search via the user/code-search APIs (when a
  `github_token` is present in `Config::api_keys`)
- GitLab group search

## Mining

- Repository tree walked for typical secret-bearing files
  (`.env`, `id_rsa`, `*.pem`, `config.json`, etc.)
- `package.json` / `requirements.txt` / `Cargo.toml` /
  `go.mod` parsed for internal package names that shouldn't be exposed.

> **Note:** This crate is currently excluded from the workspace because
> its keyhog dependencies trigger a cross-workspace `workspace = true`
> resolution issue. See `GOSSAN_LEGENDARY.md` Section B2 for the
> vendor-slice plan that re-includes it.

## License

MIT
