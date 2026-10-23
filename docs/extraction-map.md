# Extraction map

What devpit's Devflow is, file by file, and what each part becomes here.
Taken at devpit `7153771` (v0.1.44).

Legend: **(a)** portable core · **(b)** coupled to devpit, with the exact
point · **(c)** stays in devpit.

## The flow

Briefing → context → plan → execution → review → completion. Work is done only
when its evidence says so: the checks ran after the last change and passed,
every criterion has a test that passed or a proof file, the review blocks
nothing, and any own stage's gate passed.

| Concept | What it is | devpit source |
|---|---|---|
| Configuration, version 2 | `version`, `enabled`, ordered `stages` (each `uses:` a skill: `builtin/<stage>`, `project/…`, `personal/…`, `skills/…`, `<team>/…`), `review`, `decisions`. An unknown field is an error with its line | `config`, `flow`, `node`, `render`, `folder` |
| Layers | built-in → personal → each team the project `extends` → the project. A later layer wins, except on a field an earlier one `locked` | `layers` |
| Pinning | A team's ref resolved to a commit; only the person's approval writes the lockfile, with every file's hash | `pinning` |
| Setup | Detects test, lint and E2E commands with the file and line they came from, the glossary and ADRs; checks each command can run; proposes `recommended` or `custom`; previews before writing | `detect`, `available`, `preset`, `proposal`, `setup`, `playwright` |
| Brief | The epic: goal, audience, how success is checked, out of scope, context | `brief` |
| Plan | The epic's slices: criteria as checkboxes, files, verifying command, `depends_on` | `plan` |
| Checks and evidence | `stages.execution.checks` run with the context in env only; JUnit, Vitest, Jest, cargo and Go reports read; each run kept as `<item>/<time>/` | `evidence`, `runs`, `started` |
| Reviewers | Personas `spec`, `standards`, `security`, `all`, run headless on the person's own agent CLI from one packet (diff BASE..HEAD, the item, its criteria, the persona), never the session that built the change; `review.scale` sizes the review to the diff | `review`, `scale` |
| Findings | Each answer held to the findings schema, merged into one `findings.json`, verdict by `block_on` | `findings` |
| Gate | Whether the item may be called done; also holds an agent's turn at its end (Stop hook) | `gate`, `stage` |
| Decisions (Jev) | Four rubrics (brief, plan, finding, done) asked of a model provider, `shadow` or `enforce`; never the diff. Calibrated from the person's labels | `jev`, `calibrate` |
| Ad hoc review | A pull request, a commit range or a worktree reviewed without an item; `retro` mode for merged ranges | `adhoc` |
| Publish | A review drafted for its pull request (`publish.json`) and posted only after the person's yes | `publish` |
| Autopilot | Approved plan → items in the order their blockers allow | `autopilot` |
| Skills and plugin | Seven skills resolved project → personal → built-in; a Claude Code plugin and Codex hooks | `skills`, `plugin` |

## `crates/devflow` (about 20.6k lines with tests, 10.5k without)

| Module | | Coupling |
|---|---|---|
| `autopilot`, `calibrate`, `findings`, `flow`, `node`, `preset`, `proposal`, `render`, `scale`, `stage`, `started`, `brief`, `publish` | a | none; strings name `.devpit/devflow` and "card" |
| `config` | a | the `.devpit/devflow/devflow.yaml` path |
| `gate` | a | pure; its messages name `devpit_devflow_*`, `devpit_handoff`, `devpit_finish_card` |
| `plan` | a/b | `devpit_core::criteria` (the "Acceptance criteria" parser, 122 lines) |
| `playwright` | a/b | the `DEVPIT_REPORT_DIR` variable |
| `adhoc` | b | `devpit_core::criteria`, `devpit_git::plain_revision` |
| `available` | b | `devpit_pty::host_env::{command, found_on}` (login `PATH`, scrubbed env) |
| `detect`, `folder`, `setup`, `skills` | b | `devpit_core::{tree::resolve, paths::resolve_new, data_files::read_within}` |
| `evidence` | b | `devpit_steps::run` and its report parsers (about 2.1k lines); `devpit_rpc::{verdict, Report, RunState, Verdict}` |
| `jev` | b | `devpit_rpc::{DecisionsState, DevflowDecisions}` |
| `layers` | b | devpit's home for the personal and team layers; `devpit_git::pinned` |
| `pinning` | b | `devpit_git::pinned` |
| `review` | b | `devpit_agentcli::reviewing` (Claude, Codex, Cursor, Gemini); `DEVPIT_REVIEW_*` variables |
| `runs` | b | runs under devpit's home; files attached to devpit's artifacts |
| `plugin` | b | the `devpit` MCP server and its `devpit_devflow_gate` tool |
| Assets | a | `include_str!` of devpit's `flow/`: skills, personas, schema, rubrics, publish templates |

## devpit's desktop shell (`apps/desktop/src/devflow*.rs`, about 11k lines)

| File | | What it does |
|---|---|---|
| `devflow.rs` | b | the MCP tools' dispatch (status, setup, set, skill) → the MCP server and CLI here |
| `devflow_evidence.rs`, `devflow_review.rs`, `devflow_gate.rs`, `devflow_stage.rs`, `devflow_adhoc.rs`, `devflow_skills.rs` | b | git reads (review base, diff, changed since), the review packet, running checks and gates, the Stop hook → the core here; attaching to a card stays in devpit |
| `devflow_publish.rs` | b | posts with `gh` → forge adapters here |
| `devflow_plan.rs` | b | brief and plan as cards → `WorkItems` |
| `devflow_jev.rs` | b/c | the Decisions provider → `Judge`; the decision log and its screen stay |
| `devflow_autopilot.rs`, `devflow_launch.rs`, `devflow_codex.rs` | c | launching sessions, the launch line, installing into Codex |
| `devflow_asks.rs`, `devflow_screen.rs`, `devflow_card.rs`, `devflow_team.rs`, `devflow_plan_edit.rs` | c | the window, the person's clicks, the board's store |

## Elsewhere in devpit

| Item | | Note |
|---|---|---|
| `crates/agentapi/src/devflow.rs` | b | the twelve `devpit_devflow_*` tool definitions → this MCP server; devpit keeps its names as a proxy |
| `crates/rpc/src/devflow*.rs` | c | the window's contract |
| `flow/` | a | skills with evals, personas with evals, schema, rubrics, publish templates and their notices; their text names devpit about 90 times |
| `.devpit/devflow/` | c | devpit's own configuration |

## What replaces each coupling

| Coupling | Here | Default | devpit's adapter |
|---|---|---|---|
| Card, board | `WorkItems`: get, create, update body, comment, set state, `depends_on` | Markdown files under `.devflow/work/` | the board's cards; Jira, Linear and GitHub Issues later |
| Criteria parser | `criteria` in the core | | devpit re-exports it |
| Steps runner | `runner`: `sh -c`, context in `DEVFLOW_*` env, own process group, timeout, line streaming; JUnit, Vitest, Jest, cargo and Go reports | local process | may inject its own `Runner` to keep cancelling from the card |
| Host environment | `env`: login `PATH`, `found_on`, scrubbed command | | |
| Path guards | `fsguard`: resolve, resolve new, read within a ceiling | | |
| Git | `git` by shell-out: review base, diff, merge base, head, changed since, lines at, fetch a pull request, detached worktree, pinned blobs | `git` on `PATH` | |
| Agent CLIs | `ReviewAgent`: program, argv, stdin or not, answer and cost from stdout, signed out | Claude Code, Codex, Gemini CLI, Cursor, OpenCode | the same adapters |
| Hooks, plugin | the Claude Code plugin at the repository's root (skills, commands, reviewer agents, Stop and SessionStart hooks calling `devflow hook …`); the Gemini extension; ready configs for the rest | `install.sh` / `devflow register` | devpit's launch line |
| Decisions | `Judge`: rubric and state in, answer out | off; OpenRouter opt-in, as in devpit, the key in `OPENROUTER_API_KEY` or `$XDG_CONFIG_HOME/devflow/credentials` (0600) | devpit's provider and log |
| Home, runs | `devflow.yaml` or `.devflow/`; `.devflow/runs/` ignored by git; `.devflow/lock`; personal layer in `$XDG_CONFIG_HOME/devflow/`; team cache in `$XDG_CACHE_HOME/devflow/` | | devpit passes its home and keeps its runs |
| `devpit_devflow_*` tools | `devflow mcp` (stdio): `status`, `setup`, `set`, `skill`, `brief`, `plan`, `evidence`, `review`, `gate`, `stage`, `publish`, `next`, and `item`, `items`, `comment`, `start`, `finish`, `handoff` for the work items | | devpit proxies its names |
| The person's click | a terminal command with a confirmation (`devflow config set enabled true`, `devflow jev setup`, pinning a team layer), or `apply` after the person's yes; the MCP tool answers with the command to run | | the click in the window |
| Autopilot | the `next` tool: the next item by its blockers | | devpit launches the sessions |
