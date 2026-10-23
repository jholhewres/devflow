# Plan

devflow is devpit's Devflow made to run on its own. The product is an **MCP
server and a plugin**: any agent CLI or IDE that speaks MCP gets the flow's
tools, and the ones that take plugins, skills or hooks get those too. The
`devflow` binary also carries the few commands a person runs to install,
configure and check it. Nothing depends on devpit; devpit will consume the
engine through a thin adapter, in a phase of its own.
[extraction-map.md](extraction-map.md) lists what moves and why.

## Name

The project is **devflow**, by the maintainer's decision, and so are the
binary, the MCP server, the plugin and the configuration (`devflow.yaml`,
`.devflow/`). The name is taken elsewhere, which only matters for publishing:

- crates.io: `devflow` and `devflow-core` belong to another AI development
  tool ("DevFlow CLI", v2.12.0).
- npm: `devflow` (a 2022 placeholder) and `devflow-mcp`; PyPI: `devflow`.
- GitHub: `dean0x/devflow`, an agentic development harness, active.

So the **packages** carry names nobody holds, and the **binary** is
`devflow`:

| | Library | Binary package | Install |
|---|---|---|---|
| **Chosen** | `devflow-engine` | `devflow-mcp` | `cargo install devflow-mcp` |
| Alternative | `devflow-kit-core` | `devflow-kit` | `cargo install devflow-kit` |

Both pairs were free on crates.io on 2026-10-23. The release archives and
`install.sh` are the main way in, so the package names rarely show.

## Shape

```
crates/
  engine   devflow-engine: config, flow, layers, pinning, detect, setup,
           brief, plan, criteria, work items, evidence and its runner,
           findings, review packet and reviewer adapters, gate, stage,
           decisions (Jev) with its OpenRouter provider, publish, skills,
           embedded assets
  mcp      devflow-mcp, the `devflow` binary: the MCP server over stdio and
           the person's commands (setup, register, config, jev setup, doctor,
           status), and the hooks' entry points
xtask      version-sync
.claude-plugin/, skills/, commands/, agents/, hooks/
           the Claude Code plugin, at the repository's root
gemini-extension.json, GEMINI.md
           the Gemini CLI extension
integrations/
           ready configs for Codex, Cursor, OpenCode and VS Code
install.sh the one-line install
```

- **Configuration and state live in the user's repository**:
  `devflow.yaml` at the root or `.devflow/devflow.yaml`, the scripts,
  reviewers, skills and rubrics a project makes its own in `.devflow/`, work
  items in `.devflow/work/`, runs in `.devflow/runs/` (ignored by git).
  Outside it, only the personal layer and the team layers' cache under
  `$XDG_CONFIG_HOME/devflow/` and `$XDG_CACHE_HOME/devflow/`.
- **A project already on devpit's Devflow works unchanged**: its
  `.devpit/devflow/` is read where it is, with the same schema.
- **The person's decisions stay the person's.** Switching devflow on, moving
  Decisions to `enforce`, approving a team layer's pin and publishing a review
  are a terminal command with a confirmation (`devflow config set`,
  `devflow jev setup`, …) or an explicit `apply` after the person's yes; an
  MCP tool asked for one answers with the command to run.
- **Secrets never reach the repository.** The OpenRouter key is read from
  `OPENROUTER_API_KEY` or `$XDG_CONFIG_HOME/devflow/credentials` (mode 0600),
  never written to `devflow.yaml`, never printed or logged.

## The MCP tools

The twelve devpit offers, without devpit's prefix, and what replaces its
board:

| Tool | Does |
|---|---|
| `status` | the project's state, what was detected, what comes next |
| `setup`, `set` | a setup previewed and applied; one field changed |
| `skill` | a stage's skill as the project resolves it |
| `brief`, `plan` | the epic and its slices, as work items |
| `evidence` | the checks run, their reports kept as a run |
| `review`, `publish` | reviewers headless on the person's own CLIs; a PR review drafted and posted after a yes |
| `gate`, `stage` | whether the work may be called done; an own stage's gate |
| `next` | the next work item by its blockers (autopilot's pure half) |
| `item`, `items`, `comment`, `start`, `finish`, `handoff` | the work items, in place of devpit's cards |

Skills are also served as MCP prompts and resources, for clients without
plugins.

## Phases

Each phase is its own commits, pushed with CI green. Phases 1 to 8 shipped
in 0.1.0; phase 9 waits on the maintainer.

| # | Phase | Done when |
|---|---|---|
| 1 | Scaffold: rename, the MCP server answering `initialize`, `tools/list` and `status`, the plugin and extension manifests, the other tools' configs, `devflow register`, `install.sh`, CI and the release workflow | a pre-release builds and installs end to end |
| 2 | Core: devpit's `crates/devflow` and `flow/` ported into `devflow-engine`; devpit's crates replaced by modules of its own; paths and names devflow's; devpit's layout still read | devpit's Devflow tests pass here, unchanged in what they assert |
| 3 | Runner: devpit's step runner and its JUnit, Vitest, Jest, cargo and Go report parsers | the evidence tests are green |
| 4 | Adapters: `ReviewAgent` for Claude Code, Codex, Gemini CLI, Cursor and OpenCode; `gh` for publish | reviews run headless on each CLI found |
| 5 | Jev: the rubrics and Decisions with OpenRouter, opt-in, as in devpit | shadow and enforce behave as devpit's |
| 6 | MCP tools and the plugin: the tools above, the skills, commands, reviewer agents and the gate's hooks | the whole flow in Claude Code and Codex on a sample project |
| 7 | Setup CLI: `devflow setup` (detect the tools, register, write `devflow.yaml`), `config get/set`, `jev setup`, `doctor` | a clean machine set up by these alone |
| 8 | Release: docs per tool, migration notes, 0.1.0 | `install.sh` installs a release and every tool finds it |
| 9 | devpit switches to the engine (separate, on the maintainer's go) | devpit's `make test` green, same behaviour |

## Coming from devpit's Devflow

- A project's `.devpit/devflow/` is read and written where it is: its
  `devflow.yaml`, scripts, skills, reviewers, rubrics, lockfile and E2E specs.
  A project with `devflow.yaml` at its root or `.devflow/devflow.yaml` uses
  `.devflow/` instead; once `.devflow/devflow.yaml` exists it is the one read.
- Checks get `DEVFLOW_*` variables (`DEVFLOW_REPORT_DIR`, `DEVFLOW_ITEM`, …)
  and still the `DEVPIT_*` names they had, so a check script runs unchanged.
- Cards are work items, `<folder>/work/<id>.md`; the tools take `item` (and
  `card`). Runs stay in the project's folder, `<folder>/runs/`.
- Switching devflow on and Decisions' enforce were clicks in devpit; here
  they are `devflow config set enabled true` and
  `devflow config set decisions.mode enforce`, on a terminal.
- Decisions' key moves from devpit's Settings to `OPENROUTER_API_KEY` or
  `devflow jev setup`.

## Release

`VERSION` is the one version. `cargo xtask version-sync` writes it into the
plugin and marketplace manifests, the Gemini extension and the Cargo
workspace; `--check --tag vX.Y.Z` fails when any disagrees, and the release
runs it first. A `v*` tag then:

1. `verify`: versions agree, lint, tests;
2. `linux`: x86_64 and arm64 linked with zig against glibc 2.31 (Ubuntu
   20.04, Debian 11, WSL), the baseline checked on the binary;
3. `macos`: arm64 and x86_64;
4. `publish`, the only job that may write: `devflow_<version>_<os>_<arch>.tar.gz`
   and one `checksums.txt` on the GitHub Release, a pre-release when the tag
   has a `-`.

Every action is pinned by commit, with its version in a comment.
`install.sh` takes exactly these archives and checks them against
`checksums.txt` before installing.

## History

devpit's Devflow history is not carried over with `git filter-repo`: 41
commits over 12 days, each spanning devpit's desktop shell, contract, frontend
and MCP server, which filtered down to one crate would describe changes that
are not there. The `NOTICE` records the commit the code comes from.

## Risks

- **Two copies drifting** until devpit switches. Logic changes to devpit's
  `crates/devflow` either wait or are ported the same day.
- **Tool names and the skills' text** name devpit's tools; the port renames
  them, and devpit's adapter keeps its own names.
- **A confirmation on a terminal can be answered by an agent with a shell.**
  It requires a real terminal; the limit is documented.
- **A team layer's commands are somebody else's code**: pinned commit, and a
  confirmation of the exact command, as in devpit.
- **Decisions sends data to a provider**: off unless set up, never the diff,
  as in devpit.
