# Contributing

Thanks for looking. The project is early: the engine is being extracted from
devpit (see [docs/plan.md](docs/plan.md)), so the most useful thing to do
before writing code is to open an issue saying what you want to change.

## Getting set up

You need Rust (the version is pinned in `rust-toolchain.toml`; rustup installs
it on the first build) and `git`.

```sh
make check     # rustfmt --check, clippy with warnings as errors, the tests
make fmt       # after any Rust edit
```

CI runs `make lint` and `make test` on Linux and macOS, nothing else, so what
passes locally passes there.

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
