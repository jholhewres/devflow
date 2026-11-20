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
  <img src="docs/assets/devflow-flow-attack.svg" alt="briefing, context, plan, execution, review, attack when due (exploit tests in a sandbox with no network), completion; done only when checks are green after the last change, every acceptance criterion is proven, the review has no blocking findings and no confirmed exploit is open" width="100%">
</p>

Work is done when the evidence says so, not when the agent says so: checks
green after the last change, each acceptance criterion proven by a test or a
proof file, a review that blocks nothing and no confirmed exploit open.
Configuration, work items and runs live in your repository.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/jholhewres/devflow/main/install.sh | sh
devflow setup
```

The installer checks the release's checksum and registers devflow with the
agent CLIs and IDEs it finds; devflow then keeps itself current. Options and
updates: [docs/install.md](docs/install.md).

## Use

| Tool | What it gets |
|---|---|
| Claude Code | plugin: MCP tools, `/devflow:<stage>` skills, `/devflow:status`, `/devflow:pr`, reviewer subagents, the gate's Stop hook |
| Codex | MCP tools (`codex mcp add devflow -- devflow mcp`) |
| Gemini CLI | extension: MCP tools and `GEMINI.md` |
| Cursor, OpenCode, VS Code | MCP tools |

Then ask your agent for the work. It briefs it, plans it into work items
after your yes, builds each test-first, runs the checks as evidence, has it
reviewed headless on your own reviewer CLIs, attacks it when due, and calls
it done only when the gate passes.

**Security.** A security reviewer reads every change. The attack stage tries
to exploit it with tests that run in a sandbox with no network, and only an
exploit confirmed there holds the work. It reaches only what you confirmed
and publishes nothing. [How it works](docs/security.md).

## Docs

| | |
|---|---|
| [Configuration](docs/configuration.md) | commands, `devflow.yaml`, acceptance criteria, models, keys |
| [Security and attack](docs/security.md) | the security reviewer, the attack stage, its sandbox, budget, reports and CI |
| [Integrations](docs/integrations.md) | what each agent CLI and IDE gets, and how |
| [Install and updates](docs/install.md) | the installer's options, self-update |
| [Design and releases](docs/plan.md) | how devflow is built, and what each release changed |
| [SECURITY.md](SECURITY.md) | what devflow touches, and what the sandbox enforces |
| [Contributing](CONTRIBUTING.md) | how to build, test and send a change |

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE).

---

<p align="center">devflow is made by <a href="https://devpit.app">devpit.app</a>.</p>
