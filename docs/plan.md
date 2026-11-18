# Plan

devflow is devpit's Devflow made to run on its own. The product is an **MCP
server and a plugin**: any agent CLI or IDE that speaks MCP gets the flow's
tools, and the ones that take plugins, skills or hooks get those too. The
`devflow` binary also carries the few commands a person runs to install,
configure and check it. Nothing depends on devpit; devpit talks to devflow
across a process boundary (`devflow host`, 0.4.0), not by linking the engine.
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

## A host of its own

0.2.0 is what devpit (phase 9) builds on. A host that starts the agents
itself keeps what its people already see:

- `env::spawn_with` starts the engine's programs its own way, and
  `folder::pin` fixes the folder every project keeps devflow in.
- A `Dialect` carries its words — the item, the tools' names, the variables'
  prefix, the comments' labels, devflow.yaml's comments, the Decisions hints —
  and an `Assets` its own skills, personas, rubrics, schema and publish
  templates. It is passed where text is made (`gate::Looked`,
  `evidence::Given`, `review::Personas`, `folder::Layout`, `runs::Runs`, the
  `_in` functions); `Dialect::DEVFLOW` is devflow's own.

## A model per stage

0.2.1 adds to 0.2.0's API, nothing changes for a host that says nothing new:

- A stage names its `model` (a tier, `small`/`default`/`large`, or an id), and
  `models: economy|quality` picks them all; `models::session_model` is what a
  host opens a card's session with.
- `review.analysis` reads a large or sensitive diff on a large model before the
  reviewers, and its findings go to the gate like theirs.
- A review records the tokens, cost and time of each reading, and `status`
  says what the newest one spent.
- A blocking finding that comes back in a re-review asks for a design decision.

## Leaner by default

0.2.2 adds to 0.2.1's API; a devflow.yaml that names its choices runs as
before, and only the defaults change:

- The gate looks for each proof again, and an evidence run at the same tree
  is reused (`fresh`); a re-review is read once and rechecks the carried
  findings its delta touched.
- Checkboxes under a heading other than `## Acceptance criteria` are named
  and counted in the evidence (`criteria_unread`), and the gate asks for the
  heading to be renamed.
- `stages.execution.release` lists checks run once for a release, by name,
  never by the gate; the recommended preset puts the E2E suites there.
- `review.consolidate` is `none` unless the file says otherwise; a brief is
  judged only by a rubric `decisions.rubrics.briefing` names; the plan's
  rubric advises and holds only when `decisions.rubrics.plan` names it
  (`jev::holds_in`). A host still calling `jev::holds` for a plan holds it
  as before.

## Security that proves, models you can see: 0.3.0

0.3.0 is a minor version because a host that builds `plan::Slice` field
by field must add one line (below). A devflow.yaml that says nothing new
runs as before, and `models: quality` switches none of this on.

**Security that proves**

- A plan item that crosses a trust boundary (a file `review.scale.sensitive`
  matches, or `boundary: true`) names its abuse cases in `abuse`; they become
  `Abuse case:` checkboxes the gate holds the item to, and one with none is
  flagged in the plan's answer (`unguarded`, `plan::unguarded`), never
  refused.
- `review.attack: off | sensitive | per-item | release` (`off` unless said;
  a map takes `run` and `model`, `large` unless said) adds a reading by
  `devflow-security` that tries to exploit the change (`models::ATTACK`). Its
  findings carry `origin: attack` and hold the item only once the session's
  run confirmed them with an exploit test (`verified.test`); unconfirmed,
  they are followed up under `left`. Each confirmed exploit stays in
  `findings.json`'s `exploits`, and the gate wants its test green in the
  newest run. A release's attack runs by name: the review tool's
  `attack: true` (`models::attack_asked`).
- `report: sarif` reads any static analyser's SARIF 2.1.0 as evidence: each
  result a finding at its file and line (`Reported.found`), judged by the
  report and never the exit code, and never a hold. A location outside the
  project is left out unread, and the report is kept without the code and
  file contents it quotes, where a secret scanner puts the secret.
- `security.targets` lists the project's own running instances an attack
  may reach: loopback, `localhost`, `host.docker.internal` or a docker
  service's one-label name. Every address a name resolves to, as a check
  would ask for it and, for a one-label name, also alone, must be this
  machine's or a private network's (a cloud's metadata service excluded),
  within a few seconds; a name the person did not confirm is never sent to
  the resolver. One is in force only once the person confirmed it with
  `devflow config set security.targets` (kept in `consent.json`, like
  `enabled`); the MCP `set` and `setup` refuse any `security` path. The
  targets in force reach checks and readers only as
  `DEVFLOW_SECURITY_TARGETS` (and `DEVPIT_…`), through the environment a host
  builds (`security::with_targets`), and a PoC run that names another target
  is refused.
- Out of scope, and not up for debate: no step works around a model's
  refusal, a weaker model included; a third party's host is never a target.

**Models you can see**

- A `model`, wherever devflow.yaml says one, is a tier written exactly
  (`small`, `default`, `large`) or a model id of letters, digits and
  `. _ : / @ [ ] -` that starts with a letter or a digit, so it is never
  read as a flag of the CLI (`config::model_said`). Anything else is refused,
  in `config set` and in the file, with its line and what to write.
- `devflow config set` names a list's item by its place or its name: a stage
  by its name, a reviewer by its persona
  (`review.reviewers.<persona>.model`), a check by its name. A name two items
  share is refused on read and on write (`preset::find`), with their places.
- A change that lays devflow.yaml out again keeps each built-in stage's
  `model`, `models` and `review.analysis`.
- One resolver (`models::resolved`) says what each stage and reviewer runs
  on and where it came from (`models::From`: stage, reviewer, preset or
  default). The readers, the `status` tool's `models.origins` and
  `devflow status`'s table read it alike, and the table says when a tier
  leaves a CLI on its own default.

**What a host sees change**

- Public structs gained fields: `plan::Slice` (`abuse`, `boundary`; it now
  derives `Default`), `config::Config` (`security`), `config::Review`
  (`attack`), `runner::report::Reported` (`found`), and `config::Report`
  has a `Sarif` word. New: `models::{Origin, From, resolved, origins}`,
  `config::model_said`, `preset::find`, the `security` module.
  `Ask`, `runner::Context`, `evidence::{Ran, Evidence, Given}`,
  `review::{Asked, Given}` and `gate::Looked` are as they were.
- **Migration.**
  - A host that builds `plan::Slice` field by field stops compiling until
    it ends the literal with `..Default::default()`. devpit's `slice_of`
    (`apps/desktop/src/devflow_plan.rs`) takes that one line when it updates
    the engine; its plan window then carries a slice's `abuse` and
    `boundary` through an edit instead of dropping them.
  - A host that matches `config::Report` exhaustively adds the `Sarif` arm.
  - A devflow.yaml whose `model` is a mis-cased tier (`Large`) or holds a
    space no longer reads: the error names the line and what to write.
  - `models::plan` answers `agent` and `origins` besides what it did.

Next: fuzzing, and gosec/govulncheck, gitleaks, trivy and `npm audit` as
checks (any of them that writes SARIF is evidence already); the addresses a
confirmed target resolved to kept with the person's yes, so a later answer
of the network's resolver cannot move it.

## Standing on its own: 0.4.0

0.4.0 adds to 0.3.0's API; a devflow.yaml that reads under 0.3.0 reads the
same. A host now talks to devflow across a process boundary instead of
linking the engine, and the binary keeps itself current.

**It updates itself**

- Each `devflow mcp` start runs `update::on_load` on a thread of its own:
  the latest version is read off the `releases/latest` redirect (no API, no
  rate limit), `checksums.txt` and the archive are fetched over https only,
  the archive is checked against its sha256 before it is opened, the
  `devflow` in it is staged beside the binary under a name no other start
  holds, run once with `--version`, and renamed over the binary, the old one
  hard-linked to `devflow.prev` first. A lock in `$XDG_STATE_HOME/devflow/`
  keeps starts at the same moment from all downloading.
- Every local refusal comes before the network: `DEVFLOW_NO_UPDATE=1`, a
  build without the release workflow's `DEVFLOW_RELEASE` mark (a checkout's),
  a machine with no release build, a folder that is not writable. Offline or
  refused, the server is never held and one line goes to the CLI's log.
- The Claude Code plugin is then brought to the binary's version
  (`claude plugin marketplace update devflow`, `claude plugin update
  devflow@devflow` in its scope), when it is installed and behind.
- `devflow update [--check] [--json]` is the same on request, never asking
  anything: what a host runs, since it never starts `devflow mcp`.
- Release assets stay `devflow_<version>_<os>_<arch>.tar.gz` and one
  `checksums.txt`: a host's installer relies on them.

**A host across a process boundary**

- `devflow version --json` says the version and the host protocols
  (`[1]`), without the network.
- `devflow host --root DIR` serves one call over stdio: JSON-RPC 2.0, one
  object per line, `initialize` first, stderr for logs only. Protocol 1
  changes only by adding; `initialize` lists the `methods` and `tools` this
  build serves, and a method not listed is the host's own until it is.
- 0.4.0 serves `config/read`, `config/write`, `skills/list`, `skills/get`,
  `tool` (`status`) and `shutdown`. The host passes its own record of the person's two switches;
  `consent.json` is not read for them. Only `by: "person"` raises `enabled`
  or `decisions.mode: enforce`, and `security.*` stays the person's, on a
  terminal.
- devflow's skills are devflow's own, said in the host's words: a built-in
  SKILL.md names a tool as `{{tool:<name>}}`, which `initialize`'s
  `dialect.tools` maps to the host's tool (`skills::Words`); a tool it does
  not name is said as devflow says it, so devflow's own text is unchanged.
  `skills/list` and `skills/get` resolve each skill project → team →
  personal → built-in and say its layer, file and sha256.
- Next, each adding to `methods`: the gate and its hooks over the host's work
  items, evidence, review, brief and plan, publish and stage, and the host's
  screens.

**devflow.yaml keeps what it does not read**

- A change is made in the text, not by laying the file out again: a word
  swapped, a key added after its map's last, a list or map replaced, a key
  removed with its lines (`edit::set`). Comments and fields devflow does not
  read stay. Only a change inside a flow-style map is laid out again, which
  `config/write` refuses instead.
- A field this build does not read is left out of the layers too, not
  refused: a file a newer devflow wrote still reads, and `unread` names it.

## Skills in the host's words: 0.5.0

0.5.0 adds to 0.4.0's API. A project's own skills, and a team's or the
person's, are served as written.

- flow/skills/ is one text for every host. A tool is `{{tool:<name>}}`, and a
  phrase a host says otherwise is `[[devflow's words]]`, or `[[key::devflow's
  words]]` when the same words read differently elsewhere. A host's words
  replace a phrase by its key; what a host does not say is said as devflow
  says it (`skills::rendered`, `skills::Words`).
- devflow ships each host's words in flow/hosts/: devpit's in
  `devpit.json`. A host sends `"dialect": {"host": "devpit"}` and nothing
  else; its own `tools` or `phrases` win per key. Every phrase a skill marks
  has devpit's words, and every word in `devpit.json` is said somewhere.
- `tests/fixtures/devpit/` is the golden for every skill and part said in
  devpit's words, compared word by word. It was checked against devpit's
  own flow/ at 118996ca. What differs from that text does so on purpose:
  - devflow's newer text, in devpit's words: abuse cases and trust boundaries,
    the attack and its exploit tests, SARIF, models and security targets.
  - What both said, now said once, with the engine as the reference: a
    release-only E2E still gets its spec; the recommended setup's defaults;
    `consolidate`'s default `none`; the advisory plan rubric; and the review
    skill's shorter wording.
  - What only one host does: devflow's `next` tool, devpit's orchestrator
    applying a plan, the activation (a terminal command or a click), and the
    handoff's arguments.
- The review skill loads its parts only when asked: `verify`,
  `without-card`, `retro`, `publish` and `by-hand`. They are in
  `Assets::parts`, resolved through the layers like a SKILL.md
  (`skills::resolve_part`), and served by the `skill` tool's `part`, as
  `skill://devflow/devflow-review/<part>.md` resources, and by the host's
  `skills/get {name, part}`. `skills/list` names each skill's `parts`.
- 0.5.1: `skills/get` without a part, and each `skills/list` entry, carry the
  SKILL.md's `frontmatter` as JSON, so a host reads no YAML.
- 0.5.2: `initialize` takes `folder` (`.devflow` or `.devpit/devflow`) and pins
  it for the call (`folder::pin`): a project that also has another
  devflow.yaml is read and written only in the host's folder.

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
