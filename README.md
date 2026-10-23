# stagegate

An evidence-gated engineering flow for coding agents. Work goes through
**briefing → context → plan → execution → review → completion**, and it is
done only when its evidence says so: the checks ran after the last change and
passed, every acceptance criterion has a test or a proof, and independent
reviewers on your own agent CLIs found nothing that blocks it.

It runs anywhere an agent does: a `stagegate` command line and an MCP server
over stdio, for Claude Code, Codex, Gemini CLI, Cursor, OpenCode or any IDE
that speaks MCP. The configuration and the evidence live in your repository.

> **Status: early.** This is the scaffold. The engine is being extracted from
> [devpit](https://github.com/jholhewres/devpit)'s Devflow, where it runs
> today. [docs/plan.md](docs/plan.md) has the phases and
> [docs/extraction-map.md](docs/extraction-map.md) what moves.
> [Leia em português](README.pt-BR.md).

## What it does

- **Stages with gates.** Each stage is a skill the agent follows; a stage of
  your own can be gated by a command that exits 0 or by a rubric.
- **Checks as evidence.** Your test, lint and E2E commands, detected from the
  repository, run with the context in environment variables only. Their
  reports (JUnit, Vitest, Jest, cargo, Go) are kept per run.
- **Reviews that did not write the code.** Spec, standards and security
  personas review the diff headless, each on the agent CLI you pick, held to
  one findings schema; `block_on` decides what stops the work.
- **A gate at the end of the turn.** Hooks hold an agent's turn until the gate
  passes, where the CLI has a stop hook.
- **Layers.** Your personal defaults, your team's (pinned to a commit you
  approved, with fields it can lock), then the project's.
- **Pull request reviews.** A review of a PR, a range or a worktree, drafted
  and posted only after your yes.

## Install

Not published yet. From source:

```sh
cargo install --git https://github.com/jholhewres/stagegate stagegate
stagegate --help
```

## Usage today

```sh
stagegate status            # which configuration applies here
```

It reads `stagegate.yaml`, `.stagegate/stagegate.yaml`, or devpit's
`.devpit/devflow/devflow.yaml` where a project already has one.

## Develop

```sh
make check    # rustfmt --check, clippy -D warnings, tests
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE) for where the code comes from.
