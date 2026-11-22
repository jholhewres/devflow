# Plan

devflow is devpit's Devflow made to run on its own. The product is an **MCP
server and a plugin**: any agent CLI or IDE that speaks MCP gets the flow's
tools, and the ones that take plugins, skills or hooks get those too. The
`devflow` binary also carries the few commands a person runs to install,
configure and check it. Nothing depends on devpit. devpit links the
engine's stable modules (0.7.0, below) and asks `devflow host` (protocol 1)
for the project's configuration and skills.
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
xtask      version-sync (VERSION into every manifest) and plugin-sync (the
           plugin's files from flow/)
flow/      what the engine embeds: skills, personas, rubrics, schemas,
           payloads, hosts and publish
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

devpit's, without its prefix, the attack, and what replaces devpit's
board:

| Tool | Does |
|---|---|
| `status` | the project's state, what was detected, what comes next |
| `setup`, `set` | a setup previewed and applied; one field changed |
| `skill` | a stage's skill as the project resolves it |
| `brief`, `plan` | the epic and its slices, as work items |
| `evidence` | the checks run, their reports kept as a run |
| `review`, `publish` | reviewers headless on the person's own CLIs; a PR review drafted and posted after a yes |
| `attack` | the attack stage on an item or a range: exploits run in the sandbox, `verified` and `prove` |
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
  screens. 0.7.0 took the other way: devpit links the engine, and protocol 1
  stays as it is (below).

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

## The attack stage: 0.6.0

0.6.0 makes the attack a stage of its own. An attacker tries to exploit the
item's change, its exploit tests run in a sandbox with no network, and a
hypothesis is confirmed only when its test is red at the base and green at
HEAD. The details, and how to read the report: [security.md](security.md).

- `stages.attack`: `run` (`sensitive`, `per-item`, `release`, `off`),
  `model`, `test`, `sandbox` (`auto`, `bwrap`, `docker`, `off`), `image`,
  `budget` (`run_usd`, `month_usd`), `regression`, `attackers` (four at
  most) and `concurrency`. `review.attack` still reads, as its older name.
  A devflow.yaml that names no attack stage has it off, as 0.5.x did, so no
  project starts paying for attacks on an update; `devflow setup` writes
  `sensitive` for a new one, and a stage named with no `run` is
  `sensitive`.
- `devflow attack --range A..B` attacks a release range headless for CI: it
  writes SARIF and JUnit, exits 1 on a confirmed exploit in `block_on` and 2
  when it could not run, and warns of each hypothesis nothing ran.
- The gate holds an item whose attack is due and has not run, an attack
  that failed, a per-item attack older than the last change, and a
  hypothesis the sandbox confirmed in `block_on` without its proof.
- Each run writes `attack.json` and its report as markdown, JSON and SARIF
  2.1.0, with an issue draft per confirmed hypothesis. The report and the
  drafts carry only what devflow sets and devflow's words for each class of
  hole, never the attack's (`attack_report`). devflow publishes none of it.
- A threat model and the security persona's overlay feed the attack; a
  hypothesis refuted before is not tried again while its control is
  unchanged. Scanner findings become hypotheses the attack calls reachable
  or not. A workspace manifest lets it follow a flow across repositories, a
  confirmed compose stack runs on an internal network, and a range already
  in production gets a retro whose exploits stay in a vault outside the
  checkout.
- The payload repertoire (`devflow payloads list|table|add`) gives
  generic cases per class, and `regression` gives them to every attack.
- Every run's cost goes to a ledger; `month_usd` refuses a run past the
  month's budget, and the numbers suggest a run mode.
- Security targets keep the addresses they resolved to when the person
  confirmed them, so a later answer of the resolver cannot move them.
- Headless readers are held to reading (`agents::read_only`); OpenCode,
  which cannot be, is refused as a reader.
- 0.6.1: `payloads::READINGS` lists each reading of a name or an address
  `neutral` covers, each with a case only that reading refuses; a URL with
  no slashes after `http:` and the other special schemes is read for its
  host and userinfo; in backticks a relative path (`./main.rs`) or a call
  (`subprocess.call()`) is code, not a host. The README's flow shows the
  attack stage.
- 0.6.2: the `attack` tool asks the person one question through the client
  (MCP `elicitation/create`) for what only they give: devflow switched on
  (the recommended setup written where there is none, the attack stage on
  for attacks asked by name), the exploit test command found from the
  project's runner (`detect::exploit_test`), the sandbox, a budget, and
  `security.targets` with what they resolve to. Their yes is applied in
  place and the attack runs in the same call; their no writes nothing. Only
  the client's reply to that question, or a terminal, consents; each yes is
  kept in `consent.json` with how it came, when and what for. A client that
  cannot ask gets one command, `devflow setup --attack`. A range's run
  takes the session's `verified` and `prove`, recorded in the project's
  ledger (`attack::verified_into`, `attack::prove_into`), never from the
  checkout, and `doctor` tells devpit's `enabled` from devflow's own switch.
- 0.6.3: `devflow register` also puts the MCP server in Claude Code's user
  config, as the plugin names it, so a session that loads another plugin
  named devflow keeps it; `doctor` names such a plugin and `status` offers
  Claude Code the fix once.
- 0.6.4: the attack's question asks only what has no safe default (the
  command where no runner is found, the image where docker runs without
  one, the targets) and says the rest; it never asks or writes a budget,
  and one the 0.6.2/0.6.3 question prefilled holds no attack. A yes edits a
  file that names the attack as `review.attack` in place, its stage added.
  An exploit's tree gets the main worktree's dependency folders, and a
  detached tree follows its main checkout's folder.
- 0.6.5: a red exploit run confirms when its output names the test the way
  jest (` › `), vitest (` > `) or `::` join it, read whole; the markdown
  report names a proposed threat model by where the project keeps it;
  `doctor` lists the person's yeses and what the question does not ask
  again; the update's lock holds its pid, is taken over once its holder is
  gone, and a lock that cannot be made says why.
- 0.6.6: before the attacker, an attack runs again at HEAD the exploits
  earlier attacks left open, of the same work or of a range its history
  holds, and tells the attacker how each ended (`attack::open_before`,
  `run_again`, each hypothesis's `again`).
- 0.6.7: Node, Rust, Go, Python and PHP run their exploits in the sandbox,
  offline: dependency folders mounted where the project keeps them,
  cargo's registry and Go's module cache read-only, a Python venv made over
  the project's own, `composer:2` for PHP; a templated test's name
  (`it.each`) is read case by case, each runner's harness errors are never
  the hole, and a green run that ran no test refutes nothing; one hole
  several runs kept runs again once; the markdown report says who ran an
  exploit apart from its proof; a range's report says `mode: range` and
  `run_on: asked`.
- 0.6.8: neighbouring classes at one place (`tls` and `ssl`, `authn` and
  `session`; `crypto` and `tls` on one line) are one hole, run again once and merged once; `verified`
  names the test and path it ran, the sandbox's as the session's;
  attack.json's `exploits` lists every confirmed exploit with what holds
  it (`evidence` or `proof`); the markdown's first line says the mode; a
  module an editable install's `.pth` imports (setuptools' finder) is said
  again of the worktree; a Rust project's exploits start from one build of
  HEAD per attack; Pest is proven by a project of its own; the Stop hook
  reads no diff while the attack is off or kept for a release, and asks
  git for `HEAD` and the default branch once per gate read.
- 0.7.0: the engine's stable surface is declared (below); `devflow attack
  <item|range> --promote <hypothesis>` takes the place of `devflow attack
  promote <item|range> <hypothesis>`; `devflow mcp` answers `ping` while a
  tool runs, says its progress to a client that gave a `progressToken`, and
  ends a cancelled call's processes; `devflow register` gives Codex and
  Cursor the gate's Stop hook, Codex an hour per tool call and the
  project's `AGENTS.md` section, Cursor the project's rule, and knows
  Antigravity and Windsurf (Devin Desktop); the attack report names `dos`,
  `crypto` and `transport` and the classes said their own way (`stored-xss`),
  lists its confirmed exploits in JSON, says whether a cap ended a turn
  (`run_cap_hit`) and keeps on a hypothesis what a dedupe took in
  (`merged`); the attacker asserts bounds, never wall-clock time; the
  binary's main.rs only defines and dispatches the CLI, and the longest
  functions of attack.rs and review.rs are named steps.
- 0.7.1, what the 0.7.0 attack's own validation found: attack-report.json
  says `run_cap_hit`, and each hypothesis's `merged` lists what it took in
  by id and run, never a null id, with one line per hypothesis in the
  markdown; `info-disclosure` is a class, `certificate`, `mitm` and
  `insecure-transport` are `transport` in the report too, and only a
  confirmed hypothesis is said to be there; a refuted one ends at `info`
  with the attacker's severity kept as `estimated_severity`; the payload
  filter lets the documentation ranges through (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, `3fff::/20`), bare
  in an attacker's proposed case too, and refuses a real address beside
  them; variants of one root (one file, one class family, one still open)
  are one family with one fix in attack.json, attack-report.json and the
  markdown; the attacker proves a denial of service by counting or by
  comparing inputs, and an exploit that reads the clock is a `timing`
  proof, run three times and kept only when each run agrees; `devflow
  doctor` says its version first; a review sends its item to the attack only
  while it has not run on it (after every change with `per-item`); the
  skills say what the gate wants of an attack (a session-confirmed exploit
  green at any severity, a sandbox-confirmed one at `block_on` proven), the
  attack's question and what only the person sets, a release range's
  `verified` and `prove`, the review's `attack: true` answer, and the attack
  stage in the setup.
- 0.7.2, what the 0.7.1 validation found: a family holds only confirmed
  hypotheses of one file, class and cause, the attacker naming each one's
  `cause` from devflow's list and its `root` (and, by id, the cause of each
  run again), and its fix is the cause's, in devflow's words; drafts are
  one per family, then one per confirmed hypothesis no family holds, and a
  proof by timing says in its draft that it is less sure; the ask shows a
  denial of service proven by count, and a hole an earlier run proved only
  by timing is asked again by count, the count proof taking it in once it
  confirms; a refutation is read against the code changed since the attack
  that refuted it, so a range attacked again refutes nothing again, and each
  is listed with its run and id, one named again kept in `refuted_before`;
  one an earlier attack did not run, named again, carries `again`; a
  hypothesis run again keeps what it took in (`merged`); `provenance`,
  `content-spoofing`, `origin-confusion` and their like are `integrity`, and
  a class devflow does not name keeps its own name, said in the words of
  the class its attacker says is nearest (`near`).
- 0.7.3, what the 0.7.2 validation found: no confirmed hole leaves the
  lineage. Every hole earlier runs left open is read, at most twelve run
  again (the most severe first, confirmed before tried, then the one
  longest not run) and the rest are carried to the next run, said so
  (`run_again_cap`, `run_again_capped`, `carried`), with a confirmed one
  whose exploit is gone and a not-run one the attacker does not name again;
  a carried hole runs first among its severity next time, and one past the
  cap holds at `block_on`. The runs again go beside the attacker's turn,
  not before it, and `profile` says where the run's time went; an attack of
  a head nothing changed since is told so, and the threat model is written
  again only when it should change. An attacker's own hypothesis merged in
  its run keeps the number it gave it (`said_as`), listed under "Merged in
  this run" apart from the report's ids; `merged` is said once, each named
  by its run and id; a count proof that takes in a timing one carries its
  `again`; a lone draft says its cause's fix; a family draft lists its
  variants by line; attack.json keeps the class by devflow's name.

**What a host sees change**

- devpit at 366906f3, built against this engine, stops compiling in three
  places, each a line:
  - `review::Asked` gains `axes`, the personas a review without a card is
    held to (all of them when empty): end the literal with
    `..Default::default()` (`apps/desktop/src/devflow_adhoc.rs`).
  - `security::in_force` takes the confirmed addresses, `&Pins`, before its
    resolver, which now answers every name at once (`ResolveAll`, as
    `security::resolved_here_all`): devpit, which confirms no target, passes
    `&Pins::default()` (`apps/desktop/src/devflow.rs`).
  - `dialect::Assets::skills` is a slice, as `parts` already was, not an
    array of seven: map it with `.iter().map(..).collect()` and leak it as
    `parts` is (`apps/desktop/src/devflow_dialect.rs`).
- Public structs gained fields a host reads or builds with `Default`:
  `config::{Config (criteria), Stages (attack), Attack, Security (stack)}`,
  `review::{Done (axes), Ran (tries)}`, `adhoc::Standalone` (`axes`,
  `verified`), `criteria::Unread` (`empty`) and `sarif::ToolFinding`
  (`package`, `fix`). `config::Report` has `npm-audit` and `govulncheck`
  words: a host that matches it exhaustively adds their arms.
- `config::Attack::default()` is `run: off`, and `preset::starting` sets
  `sensitive`. In a change's JSON, `review.attack` still sets an attack
  that is at its default.
- `tests/fixtures/devpit-golden/` gains, on purpose, the attack stage that
  `devflow setup` now writes for a new project.
- New modules: `attack`, `attack_report`, `attack_metrics`, `payloads`, `sandbox`,
  `stack`, `vault`, `workspace`. `Ask`, `runner::Context`,
  `evidence::{Ran, Evidence, Given}`, `review::Given` and `gate::Looked`
  are as they were.
- 0.6.2 only adds to the engine: `detect::{ExploitTest, exploit_test}`,
  `attack::verified_into`, `attack::prove_into` and `sandbox::image_named`.
  `attack::verified`, `attack::prove` and `attack::Proving` are as they
  were. `stages.attack.image` now reads only as a docker image's name
  (letters, digits and `. _ / : @ -`): one that read as a flag of
  `docker run` makes the file invalid. The question
  lives in the MCP server (`ready`, `person`); a host keeps its own switches
  and asks its own way.
- 0.6.4 adds `sandbox::dependencies_for`; `folder::dir` and `folder::file`
  of a linked worktree with no configuration of its own answer its main
  worktree's, and an edit that sets a field of a stage the list lacks adds
  the stage in place.
- 0.6.5 adds `sandbox::Ran::reached`, whether the whole output named the
  exploit's test; `attack::reached` reads a test's name as the runner joins
  its parts.
- 0.6.6 adds `attack::open_before`, `runs::newest_all_with` and `git::is_ancestor`; an attack's
  report gains `run_again`, and a hypothesis run again carries `again`
  (`item`, `run`, `id`, `was`).
- 0.6.7: `sandbox::Tree::deps` and `sandbox::Seen::deps` are `sandbox::Mount`s
  (`from`, `to` inside the tree), and `Seen` gains `caches`, `writable`,
  `env` and `prelude`, filled by `sandbox::language`; `sandbox::Ran` gains
  `none_ran` (`attack::none_ran`); `detect::ExploitTest::image` is a
  `String`, and `detect::exploit_test_at` reads the project's venv, its
  `rust-toolchain` and a `composer test` script's runner.
- 0.6.8: `sandbox::Tree` gains `warm`, the `target` a Rust run starts from
  (`sandbox::warmed` builds it); `attack::confirmed_exploits` lists every
  confirmed exploit with `held_by`, and `attack::exploits` keeps only those
  held by `evidence`, as the gate wants them; `attack_report::family` names
  the family a class is told apart in, and `attack_report::on_one_line`
  the families one only on one line; `models::attack_reads_the_diff` says
  whether a diff could make the attack due.
- 0.7.0: the modules outside the stable list are `#[doc(hidden)]`, and
  `flow` is private; `review::turn_in` takes a `review::Turn` instead of
  seven arguments (`review::turn` is as it was); `call` (internal) is how a
  host cancels the call running now and hears its progress; a
  hypothesis may carry `merged`, and an attack report's budget
  `run_cap_hit`.
- 0.7.1 only adds, all of it internal: `attack_report::roots`,
  `attack::reads_clock` and `attack::TIMING_RUNS`; attack.json gains
  `families`, and a hypothesis `family`, `estimated_severity`,
  `exploit.timing` and `verified.timing`; each `merged` entry gains `id`
  and `run`; attack-report.json gains `run_cap_hit` and `families`, and its
  hypotheses `estimated_severity`, `proof_kind`, `timing` and `family`,
  with `merged` a list instead of a count; `models::attack_next` says
  whether a review sends its item to the attack.
- 0.7.2 adds `git::files_changed_between`, the files whose code changed
  between two commits; the rest is internal: `attack::still_refuted` takes
  an `attack::Since` instead of the change's files, and
  `attack::not_run_before` is new; `attack_report::CAUSES` and
  `attack_report::cause_of` name the causes; a hypothesis may carry `cause`,
  `root`, `near` and `same_as`; attack.json gains `named_again`, each
  `refuted_before` entry `line`, `run`, `id` and `named_again`, and each
  family `cause`; attack-report.json's hypotheses gain `cause`, and its
  families `cause`, `impact` and `timing`, holding only confirmed variants;
  the drafts are one per family (`f1`…), with `variants`, then one per
  confirmed hypothesis no family holds.
- 0.7.3: attack.json gains `run_again_cap`, `run_again_capped`, `carried`
  (each with `carried`, `status`, `again` and, but for a not-run one, its
  exploit's `saved`) and `profile`; `counts` gains `carried`; a hypothesis
  may carry `class_said`, its `class` now devflow's name; a `merged` entry
  of an attacker's own has `said_as` instead of `id`. attack-report.json
  gains `run_again`, `run_again_cap`, `run_again_capped`, `carried` and
  `profile`, a `merged` entry `said_as` and `by`; the metrics gain
  `wall_ms`; the SARIF keeps a carried confirmed hole, marked `carried`.
  `attack::CARRIED` names why a hole is carried; `attack::not_run_before`
  lists what was carried not run.

## The engine as a library: 0.7.0

devpit links `devflow-engine` and uses it in process: its configuration,
criteria and runs show in its own screens. Carrying every one of those types
across `devflow host` would have made each a second, JSON copy to keep in
step, for a single host written in Rust. So the engine's public surface is
declared instead, and the host stops growing.

- **Stable modules**: `adhoc`, `brief`, `calibrate`, `config`, `criteria`, `detect`, `dialect`, `env`, `evidence`, `findings`, `folder`, `fresh`, `gate`, `git`, `jev`, `layers`, `locate`, `pinning`, `plan`, `plugin`, `preset`, `proposal`, `publish`, `review`, `runner`, `runs`, `security`, `setup`, `skills`, `stage`, `started`, `work`.
- With them, the crate's own names: `Config`, `Invalid`, `Assets`,
  `Dialect`, `State`, `config_in`, `Found`, `Origin`, `Ask` and `Proposal`.
- Those are the modules devpit imported at 366906f3, where it was pinned to
  v0.5.0. A change to them is said under "What a host sees change" in the
  release that makes it. `tests/the_paths_devpit_links_stay_public.rs`
  names each path devpit names, so one that goes away fails the build.
- Every other public module is internal: `#[doc(hidden)]`, there for the
  `devflow` binary and the tests, and changed without notice (the attack,
  its reports and sandbox, the agent CLIs, the models, the vault, and the
  like). `flow` is private to the crate.
- `devflow host` stays at protocol 1, which devpit uses for `config/write`,
  `skills/get` and the `status` tool. It is kept as it is, and grows only if
  a host that cannot link Rust comes along.

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
