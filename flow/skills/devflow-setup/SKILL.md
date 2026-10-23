---
name: devflow-setup
description: Use when a person wants devflow set up, switched on, changed or fixed in a project (devflow.yaml and its stages, checks, reviewers, gate or Decisions mode), or asks what devflow would do here before it is on.
license: Apache-2.0
---

# Devflow: setup

Set devflow up for a project through its MCP tools. devflow detects what it can
(test commands, E2E tooling, the agent CLIs signed in, a Decisions key, the
glossary and ADRs) and recommends a setup; you show the preview, ask only what
detection left open, and write the file once the person says yes. Switching
devflow **on** is the person's command in a terminal, never yours.

## Ground rules

- **Preview before write.** `setup` and `set`
  preview by default and write only with `"apply": true`, which follows an
  explicit yes to the latest preview.
- **Facts are devflow's, decisions are the person's.** Detection answers what is
  in the repo; the person answers what detection could not settle.
- **One decision at a time,** each with your recommendation.
- **Let the person pick.** When your client has a tool for asking the person
  multiple-choice questions (Claude Code's `AskUserQuestion`), ask each
  decision and each yes through it, your recommendation first as
  `<answer> (Recommended)` with the reason as its description. What it asks
  about, the preview or the restate, is still shown as text first. Without
  one, ask as text, as shown below.
- **devflow does not commit.** The files it writes are the person's to commit.
- **Activation is a command.** Writing the file leaves devflow off; turning it
  on (`devflow config set enabled true`), and moving Decisions from `shadow` to
  `enforce` (`devflow config set decisions.mode enforce`), wait for the person
  to run them in a terminal.

## Steps

### 1. Read the state

Call `status`. It answers with the state (`no file`, `disabled`,
`active`, `invalid`), what devflow detected with the file each fact came from,
and the current `devflow.yaml`.

| State | Go to |
|---|---|
| `no file` | step 2 |
| `invalid` | show the error with its line and field, then step 5 to fix that field |
| `disabled` | show the file; on "switch it on", step 4's last paragraph |
| `active` | step 5 for the change the person asked for |

Done when you can say the state and list each detected fact with its source.

### 2. Preview the recommended setup

Call `setup` with `{"preset": "recommended"}` and no `apply`.
The recommended setup is: briefing and plan approved by the person; the
detected checks, each as a script under `.devflow/scripts/`; one
reviewer, with the security persona; the `devflow-done` gate; Decisions in
`shadow` when a key exists.

Show the preview as a short list (stages, each check with its command and the
file it came from, reviewers, gate, Decisions), then the open decisions from
step 3, if any. A command found that cannot run here is not recommended: its
program is not installed, or a `make` target's recipe calls one that is not.
The preview's `unavailable` says which and why; show each.

Done when the preview is shown and nothing was written.

### 3. Ask what detection left open

An open decision is one the preview could not settle from the repo:

- no test command found, or more than one candidate;
- an E2E tool configured (Playwright, Cypress) with no command that runs it;
- a reviewer CLI installed but not signed in;
- a command found that cannot run here (install what it names, or pick another);
- a Decisions key with the project opted out.

Ask the first open decision, alone:

```
**<short title>**: <the question, with the options>
→ Recommended: <answer>, because <reason>.
```

With a question tool, the answer comes back in this turn: fold it into the
setup as a `set` entry (step 4) and ask the next one. As text, end the turn and
wait, and ask the next one in the next turn. Never ask what the preview already
settled.

Done when every open decision has an answer, or there was none.

### 4. Apply, then say what is left to the person

When every decision is answered, restate the setup in one short list (or point
at the preview when nothing was asked), ending with:

```
Reply **yes** to write these files, or change any line.
```

With a question tool, ask it as `Yes, write them (Recommended)` and `Change
something` instead of the last line; otherwise end the turn. On an explicit,
unconditional yes to that restate, or the yes option picked, call:

```json
{
  "preset": "recommended",
  "set": { "stages.execution.checks": [{ "name": "unit", "run": "make test", "report": "junit" }] },
  "apply": true
}
```

`set` holds the answers as dotted paths over the preset; leave it out when
nothing was asked. Use `"preset": "custom"` only when the person rejected the
recommended setup as a whole.

An answer with `"applied": false` wrote nothing: the setup changed since the
preview the person saw (a `devflow config` command run, a key saved). Show
them the new preview and ask again.

Reply with the files devflow wrote (`.devflow/devflow.yaml`, `scripts/`,
`.gitignore` ignoring `runs/`) and any check script it removed (`remove`: one
it wrote that no check runs) or left (`unused`: one the person changed), that
they are theirs to commit on the default branch, and whether
devflow is on as the tool's note says: unless the person already switched it
on, **devflow is still off until they run `devflow config set enabled true` in
a terminal**. End the turn.

Done when the tool reported the files written and the reply says that
activation waits for their command.

### 5. Change one field

Call `set` with the field as a dotted path and its new value,
without `apply`:

```json
{ "path": "review.block_on", "value": ["critical"] }
```

More reviewers are more items of `review.reviewers`, each
`{ "agent": "codex", "persona": "devflow-spec", "model": "…" }` on that CLI's
own sign-in; `review.consolidate` says how their findings become one list:
`jev` (Decisions, else a model pass), `agent` (one model pass) or `none`.
`review.scale` (off unless set; `true`, or `{ small_lines, sensitive }`)
sends a small diff that touches no sensitive path to one `devflow-all`
reviewer instead. devflow's personas are read from devflow, never copied: to
customize one, write it as `.devflow/reviewers/<a new name>.md` and
name that persona in `review.reviewers`. A check added here gets a script
under `scripts/` of its own, as the setup's do.

A check's `report` is the file it writes into `$DEVFLOW_REPORT_DIR` for devflow
to read test by test (`junit`, `vitest`, `jest`, `cargo`, `go`); one that writes
none, and leaves it out or says `none`, is judged by its exit code: 0 passed,
127 not run (its command was not found), anything else failed.

Two optional fields keep a check off what it shares. `requires` is a probe run
first, such as `pg_isready -q`: when it fails the check is not run rather than
red, since what it needs is down, not the code. `exclusive` names a lock, such
as `postgres-test`: checks naming the same one never run at once, across items
and worktrees, and the one holding it is given `$DEVFLOW_LOCK_POSTGRES_TEST`.

Show the before and after, ask for a yes (through the question tool when
there is one), then call it again with `"apply": true`. `enabled` and `decisions.mode: enforce` go through the
person's command, like activation: tell them which `devflow config set` to run
instead of setting them.

Done when the tool reported the change written, or the reply says which command
the change waits for.
