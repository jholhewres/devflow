<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/devflow-logo-dark.png">
    <img src="docs/assets/devflow-logo.png" alt="devflow, by devpit.app" width="420">
  </picture>
</p>

<p align="center">
  An evidence-gated engineering flow for coding agents, as an MCP server and plugin.
</p>

<p align="center">
  <b>English</b> &middot; <a href="README.pt-BR.md">Português</a>
</p>

<p align="center">
  <img src="docs/assets/devflow-flow.svg" alt="briefing, context, plan, execution, review, completion; done only when checks are green after the last change, every acceptance criterion is proven and the review has no blocking findings" width="100%">
</p>

Work is done when the evidence says so, not when the agent says so: checks
green after the last change, each acceptance criterion proven by a test or a
proof file, a review that blocks nothing. Configuration, work items and runs
live in your repository.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/jholhewres/devflow/main/install.sh | sh -s -- --version=0.0.1-rc.2
devflow setup
```

`install.sh` checks the release's checksum, puts `devflow` in `~/.local/bin`
and registers it with the agent CLIs and IDEs it finds (`--tools=`,
`--dry-run`, `--uninstall`). Only pre-releases exist so far, hence
`--version`. `devflow setup` writes the project's `devflow.yaml` and switches
devflow on, asking first.

## Use

| Tool | What it gets |
|---|---|
| Claude Code | plugin: MCP tools, `/devflow:<stage>` skills, `/devflow:status`, `/devflow:pr`, reviewer subagents, the gate's Stop hook |
| Codex | MCP tools (`codex mcp add devflow -- devflow mcp`) |
| Gemini CLI | extension: MCP tools and `GEMINI.md` |
| Cursor, OpenCode, VS Code | MCP tools |

Then ask your agent for the work. It briefs it, plans it into work items
(`.devflow/work/`) after your yes, builds each test-first, runs the checks
(`evidence`), has it reviewed headless on your own reviewer CLIs (`review`),
and may call it done only when `gate` passes.

| Command | Does |
|---|---|
| `devflow setup` · `doctor` | set up this machine and project · check them |
| `devflow config get` · `set <path> <value>` | read or change `devflow.yaml` |
| `devflow jev setup` · `test` | Decisions (Jev) through OpenRouter, opt-in |

The OpenRouter key is read from `OPENROUTER_API_KEY` or kept in
`~/.config/devflow/credentials` (mode 0600): never in the repository, never
printed. A project on devpit's Devflow works unchanged: its
`.devpit/devflow/` is read where it is.

More: [integrations](docs/integrations.md) · [plan](docs/plan.md) ·
[contributing](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE).

---

<p align="center">devflow is made by <a href="https://devpit.app">devpit.app</a>.</p>
