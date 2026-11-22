# Contributing

Thanks for looking. devflow is a standalone engine and MCP server, released
as 0.x (see [docs/plan.md](docs/plan.md) for its shape and history). The
most useful thing to do before writing code is to open an issue saying what
you want to change.

## Getting set up

You need Rust (the version is pinned in `rust-toolchain.toml`; rustup installs
it on the first build) and `git`.

```sh
make check     # rustfmt --check, clippy with warnings as errors, the tests
make fmt       # after any Rust edit
```

CI runs three jobs: `make lint` and `make test` on Linux and on macOS, and
`manifests`, which checks that every manifest agrees with `VERSION`
(`cargo xtask version-sync --check`), that the plugin's files are the
flow's (`cargo xtask plugin-sync --check`) and that `install.sh` parses
(`sh -n`). Run those too and what passes locally passes there.

## Rules that have teeth

- **A test calls the rule, not a copy of it.** Extract the rule into a named
  function and have the test call it. Then break the rule on purpose and watch
  the test fail; a test that still passes is decoration.
- **Integration tests are named for the behaviour they pin**, as a sentence:
  `the_status_names_the_configuration.rs`.
- **Every path is resolved through symlinks and checked against the project's
  root** before it is read or written.
- **Context reaches a command only through environment variables.**
- **Every read of an externally supplied size has a ceiling** before the
  allocation.
- **A command either works or is not there.** No subcommand, tool or flag that
  does nothing yet.

## Style

Match the surrounding code. Comments say *why*, briefly; one or two lines.
Everything versioned is in English, except `README.pt-BR.md`.

## Commits and pull requests

Short, objective, English, one theme per commit. No `Co-Authored-By` or other
attribution trailers.

By contributing you agree that your contribution is licensed under the
Apache License 2.0, as the rest of the project.
