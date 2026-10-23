# devflow

An evidence-gated engineering flow for coding agents, served as an **MCP
server and plugin**. Work goes through **briefing → context → plan →
execution → review → completion**, and it is done only when its evidence says
so: the checks ran after the last change and passed, every acceptance
criterion has a test or a proof, and independent reviewers on your own agent
CLIs found nothing that blocks it.

It works with Claude Code (as a plugin), Codex, Gemini CLI (as an extension),
Cursor, OpenCode, VS Code and any other MCP client. The configuration and the
evidence live in your repository.

> **Status: early.** The MCP server, the installer and the release are in
> place; the engine is being ported from
> [devpit](https://github.com/jholhewres/devpit)'s Devflow, where it runs
> today. [docs/plan.md](docs/plan.md) has the phases.
> [Leia em português](README.pt-BR.md).

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/jholhewres/devflow/main/install.sh | sh
```

It downloads the release for your machine, checks it against the release's
`checksums.txt`, puts `devflow` in `~/.local/bin` and registers it with every
agent CLI and IDE it finds. Options: `--tools=claude,codex`, `--dry-run`,
`--uninstall`, `--version=X.Y.Z`; see [docs/integrations.md](docs/integrations.md).

Claude Code only:

```text
/plugin marketplace add jholhewres/devflow
/plugin install devflow@devflow
```

The plugin starts `devflow mcp`, so the binary must be on `PATH`.

## What it does

- **Stages with gates.** Each stage is a skill the agent follows; a stage of
  your own can be gated by a command that exits 0 or by a rubric.
- **Checks as evidence.** Your test, lint and E2E commands, detected from the
  repository, run with the context in environment variables only. Their
  reports (JUnit, Vitest, Jest, cargo, Go) are kept per run.
- **Reviews that did not write the code.** Spec, standards and security
  personas review the diff headless, each on the agent CLI you pick, held to
  one findings schema; `block_on` decides what stops the work.
- **A gate at the end of the turn**, through hooks where the CLI has them.
- **Layers.** Your personal defaults, your team's (pinned to a commit you
  approved, with fields it can lock), then the project's.
- **Decisions (Jev)**, opt-in: typed rubrics judged by a model through
  OpenRouter, in shadow or enforce.
- **Pull request reviews**, drafted and posted only after your yes.

## Today

```sh
devflow status               # which configuration applies here
devflow register --dry-run   # what registering would change
devflow mcp                  # the server; agent CLIs start it
```

The server answers `status`. The rest of the tools arrive with the port.

## Develop

```sh
make check            # rustfmt --check, clippy -D warnings, tests, versions
make sync-version     # after changing VERSION
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE) for where the code comes from.
