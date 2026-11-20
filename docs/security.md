# Security and attack

devflow looks at a change's security twice, in different ways:

- **The security reviewer** reads the change during review and judges it.
- **The attack** is a stage of its own after review: it tries to exploit
  the change and keeps only what an exploit test proved.

This page describes them as they work in 0.6, limits included.

## The security reviewer

`devflow-security` is the review's security axis, beside `devflow-spec` and
`devflow-standards`. It reads the review packet (BASE, HEAD, the diff, the
work item, its criteria and the evidence), names the trust boundaries the
diff touches, runs STRIDE over each, and answers with findings, each with a
severity, the line it quotes and, for a `critical` or `high`, a PoC: the input
an attacker sends and what happens.

- **When it runs:** on every review. It runs headless on the agent CLI that
  `review.reviewers` names for it; a persona not listed there is reviewed by
  the session itself. With `review.scale`, a small diff that touches no
  sensitive path, and any re-review, is read by one `devflow-all` reviewer
  that covers all three axes.
- **What it may do:** read files. It changes nothing and runs nothing (see
  "What a headless reader may do").
- **What holds the item:** a finding whose severity is in `review.block_on`
  (`[critical, high]` by default).
- **`review.verify`** asks the session to run the PoC of each critical and
  high and record it with the review tool's `verified`: `off` (the default)
  does not ask, `advise` asks, `required` also counts a high that no PoC run
  confirmed as a medium.

```sh
devflow config set review.reviewers '[{"agent":"claude","persona":"devflow-security"}]'
devflow config set review.verify advise
```

## What a headless reader may do

A reviewer or attacker devflow starts headless is there to read. Every
exploit it writes runs in the attack's sandbox, never in the reader's own
session. How firmly each CLI is held to reading depends on the CLI:

| CLI | Started with | Held by |
|---|---|---|
| Claude Code | only the Read, Grep and Glob tools (`--tools`) | devflow: it has no shell, whatever the person's settings allow |
| Codex | its `read-only` sandbox | Codex: it may run commands that read, never write or reach the network |
| Cursor | ask mode (`--mode ask`) | Cursor's own mode and the person's settings |
| Gemini | plan mode (`--approval-mode plan`) | Gemini's own mode; settings that turn plan mode off fall back to its default |
| OpenCode | nothing: it is refused as a headless reader | no mode devflow can hold it to |

So Claude Code is the reader devflow holds hardest; with Cursor and Gemini,
keep their own permission settings as tight as the session's. A diff too
long for the packet is written beside it in full, for the reader to read.

## The attack stage

The attack reads the change as `devflow-security` told to prove each risk
instead of listing it. It starts from the threat model, tries to exploit
each trust boundary, and answers with hypotheses. Each one is `tried` with an
exploit test that fails while the hole is there and passes once it is fixed,
or `refuted`, or `not_run`, with its reason. devflow runs each exploit in a
sandbox: one that fails there is `confirmed`, one that passes is `refuted`.

- **When it runs** (`stages.attack.run`; `review.attack` is its older name
  and still reads, but a devflow.yaml says it once):

  | Value | Runs |
  |---|---|
  | `sensitive` | the default: after a review whose diff `review.scale` does not call small (past `small_lines`, or touching a sensitive path) |
  | `per-item` | after every review, and again after each change |
  | `release` | only when asked by name, once for a release |
  | `off` | never |

- **Model:** `large` unless `stages.attack.model` says another tier or a
  model id, on the first reviewer's CLI. `stages.attack.attackers` declares
  up to four attackers instead (see "Several attackers").
- **How it is asked for:** the `attack` tool on a work item, after its
  review, or `devflow attack <item>` in a terminal. `attack` with `base` and
  `head` and no item attacks a range (see "A retro of code in production").
- **What it keeps:** `attack.json` in a run of the item, each exploit's code
  in the run's `exploits/` folder, never the checkout, and the reports below.
- **What holds the item:** where the attack is due, the gate waits for it to
  have run, after the last change with `per-item`. An attack that failed to
  run holds the item until it runs again. A hypothesis the sandbox confirmed,
  with its severity in `review.block_on`, holds the item until it is proven:
  `attack` with `run` and `prove` (or `devflow attack <item> --prove <run>`)
  runs its exploit again at the commit it was confirmed on, where it must
  fail, and at HEAD, where it must pass. From then on its exploit test must
  be green in the newest evidence. A hypothesis no sandbox ran is followed up
  and holds nothing.

```yaml
# devflow.yaml, version 2
stages:
  - uses: builtin/review
  - uses: builtin/attack
    run: sensitive
    model: large
    test: sh scripts/run-exploit.sh   # runs one exploit, given $DEVFLOW_EXPLOIT
    sandbox: auto                      # auto, bwrap, docker or off
    budget: { run_usd: 5, month_usd: 50 }
    concurrency: 1                     # attackers at once, when several are declared
```

```sh
devflow config set stages.attack.run per-item
devflow config set stages.attack.run off   # as 0.5.x did when review.attack was unset
```

### Targets: what an attack may reach

By default an attack reaches nothing but the checkout: its own tests and a
throwaway test. To let it send requests to the project's own running
instances, list them in `security.targets`:

```sh
devflow config set security.targets '["http://localhost:8080"]'
```

- Only loopback, `localhost`, `host.docker.internal` and a docker service's
  one-label name are accepted. Every address a name resolves to must be this
  machine's or a private network's; a cloud's metadata address never is.
- A target is in force only after the person confirmed it **on a terminal**
  with `devflow config set security.targets`. The MCP `set` and `setup` tools
  refuse any `security` path, and a devflow.yaml an agent edited is not the
  person's yes.
- The addresses a name resolves to when the person confirms it are kept with
  the yes (`consent.json`). A later answer of the resolver that leads
  anywhere else takes the target out of force, as does a name confirmed
  before devflow kept them: running the same `devflow config set` again
  shows where it resolves now and asks again. Every name is resolved at
  once, under one deadline of a few seconds.
- The targets in force reach checks and readers only as
  `DEVFLOW_SECURITY_TARGETS`. A PoC run recorded against any other target is
  refused.

### What it never does

- Send a request to a third party's host, or to a cloud's metadata service.
- Work around a model's refusal: no retry with another prompt, and no weaker
  model or other agent in its place.
- Publish anything: hypotheses, reports and issue drafts stay in the run's
  files until the person acts.

## A retro of code in production

A range already merged can be reviewed for security alone: `review` with
`base`, `head`, `mode: "retro"` and `axes: ["security"]`. Only the security
reviewer reads it. The exploit tests that prove its findings are written to a
vault, a folder in devflow's cache outside the repository, and its report
says each finding confirmed, not confirmed or not run, with where its exploit
is. A retro is never held: what would have held it is followed up, and each
medium or worse defect carries `impact`, the read-only query that shows what
it touched since the deploy.

An attack on a range (`attack` with `base` and `head`, no item) keeps its run
and exploits in the same vault, and its spend counts against the project's
month like any other. `devflow attack promote <range> <hypothesis> --run
<run>` copies one exploit into the repository at its own path once its fix
lands, refusing a path that leads out of it. devflow refuses a vault that
would resolve inside the checkout before it makes any folder of it.

## How to read the hypotheses

| Status | Means | Effect |
|---|---|---|
| `confirmed` | the exploit test failed as the hypothesis said, in the sandbox or in the session's recorded run | holds the item when its severity is in `block_on`, until proven; its test must then stay green |
| `refuted` | the exploit ran and the hole is not there, or the attacker found the control that stops it | holds nothing; not tried again while the control's file is unchanged (`refuted_before`) |
| `tried` | an exploit test is written but no sandbox ran it, with why | followed up: the session runs it and records it with `run` and `verified` |
| `not_run` | the attacker could not try it here, with why (no target, a destructive step) | followed up, holds nothing |

A review's finding takes a recorded PoC run the same way: the review tool's
`verified`, on any finding, `confirmed`, `refuted` or `not_run`. An attack
finding in a review (the review tool's `attack: true`) with no recorded run,
its description starting `unconfirmed:`, is followed up as well.

## Budget and metrics

The attack runs on a large model and reads more than a reviewer. On one
measured change of about 700 lines, one attack took 6 to 8 minutes and
US$ 1.40 to 1.80 ([measurements](measurements/2026-11-presets.md)).
`per-item` pays that after every change, so `sensitive` or `release` is the
usual choice. `stages.attack.budget` caps it:

- `run_usd` caps one run: the attacker's turn stops there, the report says
  what capped it (`run_capped_by`), and several attackers share it.
- `month_usd` refuses a run before it starts once the month's attacks spent
  it. A ledger devflow cannot read refuses too: it never counts as nothing
  spent.

Each run's numbers are kept on its report and in the project's ledger,
beside its runs and never in the repository. `devflow status --attack` adds
them up: runs, cost, what was confirmed, what the review's security reader
missed, and the run mode those numbers suggest.

## Reports and issue drafts

Each attack run writes its report beside `attack.json`: markdown
(`attack-report.md`), JSON (`attack-report.json`) and SARIF 2.1.0
(`attack-report.sarif`), and one issue draft per confirmed hypothesis under
`drafts/`. No exploit's code is in any of them. `devflow attack <item>
--report <run> --format md|json|sarif` prints one. devflow publishes none of
them: they are the host's to show and to send where the person says.

Every text in them goes through a scrub first: secrets, tokens, e-mail
addresses and phone numbers are taken out, and so is every string the
exploits send, so a payload never reaches a draft. How the scrub tells a
secret from the rest is still being settled: this part is pending.

## In CI

Pending: how a release range is attacked in CI, and failing on a confirmed
exploit, is described once that lands.

## A flow across repositories

A hole can start in one repository and land in another: an API writes a
job, a worker reads it. A workspace manifest, `workspace.json` in devflow's
folder, names the repositories beside the project and the flows between
them, each with a writer, a reader and the contract. `attack` with `flow`
(or `devflow attack <item> --flow <name>`) reads both sides and the contract
with the change, and a hole across them names the fix on each side. The root
is the project or the folder above it. Every repository is a git repository
under it, and every side is a file inside its repository that is never
hidden and never reached through a link. Any other path is refused. No host
is needed.

## Several attackers

`stages.attack.attackers` declares up to four attackers, each an `agent` and
a `model`, to cover each other's blind spots. They run one after another
unless `stages.attack.concurrency` says how many at once; each has the run's
time limit, so one after another takes up to that many times as long. Their hypotheses
are consolidated: the same file and class within a few lines, found by two
attackers, are one, naming every attacker that found it; one attacker's own
hypotheses stay apart. The run's budget is shared out among them. An
attacker that refuses or fails leaves its part not run, and devflow switches
no other agent or model in its place. Each attacker's cost and time are kept
on the report.

## What the attack knows of your project

With the attack stage, a project gives the attack its own context in two
files of devflow's folder. `threat-model.md` lists the assets, the untrusted
inputs, the trust boundaries and their controls; each attack reads it and
proposes its update as a diff, which you take or leave.
`reviewers/devflow-security.overlay.md` adds the project's context to the
security persona: it comes after the persona's rules and cannot remove one.
`devflow persona show devflow-security` prints what a reader reads, and each
run's context names the persona and the overlay by their digests.

## Scanner findings, reachable or not

A check whose `report` is `sarif`, `npm-audit` or `govulncheck` is read as
findings at their package and place, from the report the check writes into
`$DEVFLOW_REPORT_DIR` (for example `npm audit --json >
"$DEVFLOW_REPORT_DIR/audit.json"`, or `govulncheck -json ./... >
"$DEVFLOW_REPORT_DIR/vuln.json"`). Such a check passes or fails by its
report, not its exit code. The attack is given each one and says whether untrusted input reaches
it, with the call path. Its report lists the reachable ones with their fix
apart from the rest, the noise a scanner alone leaves you with.

## Payload repertoire

devflow ships generic cases by attack class: SSRF, ReDoS, path traversal, SQL
and NoSQL injection, XXE, deserialization and prompt injection. Each case is a neutral input
and what safe code does with it. A URL's host is loopback or private on port
1, or a name that resolves nowhere; a bare address leads inside; no name or
e-mail address ends in a real place, and no case names a real project or
person. A real place is any two-letter country's, any top-level name IANA
delegates, or a name networks use inside (`internal`, `local`, `corp`…). The
IANA names are a dated snapshot, `flow/payloads/tlds-alpha-by-domain.txt`;
to refresh it, download <https://data.iana.org/TLD/tlds-alpha-by-domain.txt>
over it and update the version and size the payloads test pins. `devflow payloads table <class> --runner
jest|vitest|go|pytest` prints a test table with a `check` function you fill
in for the code under test. `stages.attack.regression: [ssrf, redos]` gives
those classes' cases to every attack. A case an attack proposes stays in its
report until you keep it with `devflow payloads add <item> <case>` on a
terminal, in `payloads/<class>.json` of devflow's folder.

The prompt-injection table tests the code that builds a model's messages,
with no model called. Each case is text a user, a tool or a document wrote.
You fill in `build`, which gives the text to your message builder and returns
the messages it built. A case is followed by its markers, runs of two or more
words it holds; a marker your builder says on its own is not counted. The table fails when the text became a system,
developer or assistant message, or when a tool's output reached the model
outside its tool role or tool_result block. Whether a tool that writes asks
the person first, and how a delimiter is escaped, is left to the security
review.

## A local stack to attack

`security.stack` names a compose file of the project. You confirm it in a
terminal with `devflow config set security.stack compose.yaml`. The terminal
lists its services and the SHA-256 of the stack as compose resolves it, so a
change to anything it pulls in (an `.env`, an include) is not in force until
you confirm it again. MCP `set` and `setup` refuse the field.

Before an attack, devflow starts the stack on a network of its own that
docker makes internal, so nothing on it reaches beyond it. The exploits run
in the docker sandbox (chosen whenever the sandbox is `auto`), attached only
to that network, with the services' exposed ports as targets. Only an exploit
that says which target it reaches joins the network; every other exploit has
no network at all. Each service runs on the image it was confirmed with,
pinned by its id, and an image that is not on this machine is refused. The
stack is taken down when the attack is done, even when it failed. An exploit
confirmed against the stack is proven at HEAD only, since the stack runs the
checkout as it is.

A stack may say only what keeps it on its network. Each service has an
image and nothing beyond these keys: command, entrypoint, environment,
expose, healthcheck, depends_on, working_dir, user, labels, restart, tmpfs,
read_only, stop_signal, stop_grace_period, networks (only devflow's), plain
volumes, binds from inside the project, init and hostname.
Anything else is refused before anything starts: a build, a published port,
the host's network, pid or ipc, privileges, devices, secrets and configs.

## Where exploits run

Set `stages.attack.test` to the command that runs one exploit test (it gets
the test's path as `$DEVFLOW_EXPLOIT`), and devflow runs each exploit itself
in a throwaway worktree of HEAD, as your own user: in bwrap with a network
namespace of its own, or in docker with no network and the image
`stages.attack.image` names. With a stack, an exploit that names one of its
targets joins only the stack's internal network. Each exploit gets a
worktree of its own, dropped whole after it ran. The checkout is out of
reach there, only the throwaway copy is written, and time, CPU and memory
are capped: docker caps the container's memory, CPUs and process count;
bwrap hides `/run` and your home folder (showing back only the project's
dependency folders and the toolchains on your `PATH`, read-only), and its
CPU and memory caps hold per process, with no cap on how many it starts.
Where neither sandbox works (bwrap needs unprivileged user namespaces;
docker needs the image), or the command is not set, the exploit stays
`tried` with the reason, and the session runs it.

## Limits today

- **A headless reader cannot run its own PoCs.** Reviewers and attackers only
  read, so every exploit test is written by the attack and run in the sandbox
  or by the session, which then records it with `verified`.
- **Where no sandbox works, the session runs the exploits.** devflow does not
  sandbox the agent's own shell: it gives the targets in force and asks that
  nothing else be reached, but a command an agent runs runs with your
  permissions. See [SECURITY.md](../SECURITY.md) for what the sandbox
  enforces and what it does not.
- **A stack's exploits are proven at HEAD only,** since the stack runs the
  checkout as it is.
