# Working in this repository

Instructions for any coding agent or contributor. `CLAUDE.md` points here so a
rule lives in one place.

Read [docs/plan.md](docs/plan.md) and [docs/extraction-map.md](docs/extraction-map.md)
before a structural change.

- Everything versioned is in English, except `README.pt-BR.md`.
- `make check` before saying done; `make fmt` after any Rust edit.
- No dependency on any devpit crate. devpit consumes devflow, never the
  reverse.
- The rules in [CONTRIBUTING.md](CONTRIBUTING.md) apply: tests call the rule,
  paths are checked against the root, context reaches commands only through
  environment variables, no command that does nothing.
- Commits: short, English, one theme, no trailers. Never commit unless asked.
