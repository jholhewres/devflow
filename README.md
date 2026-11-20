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
curl -fsSL https://raw.githubusercontent.com/jholhewres/devflow/main/install.sh | sh
devflow setup
```

`install.sh` checks the release's checksum, puts `devflow` in `~/.local/bin`
and registers it with the agent CLIs and IDEs it finds (`--tools=`,
`--dry-run`, `--uninstall`, `--version=`). `devflow setup` writes the project's `devflow.yaml` and switches
devflow on, asking first.

devflow keeps itself current: each time an agent CLI starts `devflow mcp`,
a background thread asks GitHub for the latest release and installs a newer
one over the binary. The archive must match the release's `checksums.txt`,
and the new binary must run before it replaces the old one, which is kept as
`devflow.prev`. The Claude Code plugin is brought to the same version. The
server answers at once; offline, it logs one line and carries on; the next
start runs the new version. `DEVFLOW_NO_UPDATE=1` switches it off, and a
build from a checkout never replaces itself. `devflow update` does it now
(`--check` only looks, `--json` answers one line).

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
| `devflow update` · `version --json` | install the latest release now · this version and the host protocols |
| `devflow host` | one call from a host app (devpit) over stdio JSON-RPC |

A work item's acceptance criteria are the checkboxes under
`## Acceptance criteria`. A project that writes them under a heading of its
own names it, and both are read, in the evidence and at the gate:
`devflow config set criteria.headings '["Done when"]'`.

The OpenRouter key is read from `OPENROUTER_API_KEY` or kept in
`~/.config/devflow/credentials` (mode 0600): never in the repository, never
printed. A project on devpit's Devflow works unchanged: its
`.devpit/devflow/` is read where it is.

Models: `models: economy` runs the work and the reviewers on a small model
and an analysis of a large or sensitive diff on a large one; unset, only the
work's session opens small; `models: quality` runs everything large. A stage's own `model`
(`small`, `default`, `large` or a model id) and a reviewer's `model` win over
the preset. A `devflow.yaml` that names no preset reviews as it did;
`models: economy` is the one to write ([measured](docs/measurements/2026-11-presets.md)). A model
is a tier, exactly, or a model id; anything else is refused with what to
write. To plan and review on a large model and execute on a small one:

```sh
devflow config set stages.plan.model large
devflow config set stages.execution.model small
devflow config set stages.review.model large   # every reviewer that names no model of its own
devflow config set review.reviewers.devflow-security.model claude-opus-5-5   # one reviewer, by its persona
devflow status   # each stage's and reviewer's model, and where it came from
```

`status` also says what the newest review spent by stage and model
(`spent`).

## Security and attack

Two things look at a change's security. The **security reviewer**
(`devflow-security`) reads it during review, like the spec and standards
reviewers, and its critical and high findings hold the work. The **attack**
is a stage of its own after review: it tries to exploit the change and
answers with hypotheses, each with an exploit test. devflow runs each exploit
in a sandbox (bwrap, or docker with no network), in a throwaway worktree, and
only one that fails there, `confirmed`, holds the work, until it is proven
red at its base and green at HEAD.

```sh
devflow config set stages.attack.run per-item   # sensitive (the default), per-item, release or off
devflow config set stages.attack.test 'sh scripts/run-exploit.sh'   # runs one exploit, given $DEVFLOW_EXPLOIT
devflow config set stages.attack.budget '{"run_usd":5,"month_usd":50}'
devflow config set security.targets '["http://localhost:8080"]'   # asks you to confirm each, on a terminal
devflow status --attack   # what the attacks cost and confirmed, and the mode they suggest
```

`review.attack` is the stage's older name and still reads. A devflow.yaml
that names no attack stage has it on as `sensitive`: past a small diff, or on
a sensitive path, the gate waits for it; `stages.attack.run off` is how 0.5.x
behaved. An attack reaches only the project's own instances you confirmed
(loopback, `localhost`, `host.docker.internal`, docker service names) or a
compose stack you confirmed, on an internal network; never a third party or
a cloud's metadata, and it never works around a model's refusal. Each run
writes its report as markdown, JSON and SARIF, with an issue draft per
confirmed hole, and publishes none of it. A range already in production gets
a security-only retro whose exploits stay in a vault outside the repository.
`devflow attack --range A..B` attacks a release range in CI, writes SARIF
and JUnit, and fails on a confirmed exploit. Plan items that cross a trust boundary
name their abuse cases, each a criterion proven by a test.

devflow does not sandbox the agent's own shell. How each piece works, what
it costs and how to read the hypotheses: [docs/security.md](docs/security.md);
what the sandbox enforces and what it does not: [SECURITY.md](SECURITY.md).

More: [integrations](docs/integrations.md) · [security](docs/security.md) · [plan](docs/plan.md) ·
[contributing](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE).

---

<p align="center">devflow is made by <a href="https://devpit.app">devpit.app</a>.</p>
