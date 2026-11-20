# Security and attack

devflow looks at a change's security twice, in different ways:

- **The security reviewer** reads the change during review and judges it.
- **The attack** tries to exploit the change and keeps only what it proved.

This page describes them as they work in 0.5.x, limits included.

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
- **What it may do:** read files and run git's reading commands. It changes
  nothing and runs nothing else.
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

## The attack

`review.attack` adds one more reading of the change by `devflow-security`,
told to prove each risk instead of listing it: start from the threat model,
try to exploit each boundary with the project's own tests or a throwaway test,
and give each reproduced hypothesis an exploit test that fails while the hole
is there and passes once it is fixed.

- **When it runs** (`review.attack.run`):

  | Value | Runs |
  |---|---|
  | `off` | never (the default) |
  | `sensitive` | on a review whose diff `review.scale` does not call small: past `small_lines`, or touching a sensitive path |
  | `per-item` | on every review, re-reviews included |
  | `release` | only when asked by name: the review tool's `attack: true`, once for a release |

- **Model:** `large` unless `review.attack.model` says another tier or a
  model id.
- **What holds the item:** an attack finding holds the item only once the
  session ran its exploit test, saw it fail, and recorded it with the review
  tool's `verified` (`result: confirmed` and the `test`), and its severity is
  in `block_on`. An attack finding with no such run is followed up (`left`)
  and holds nothing. A confirmed exploit stays in findings.json's `exploits`,
  and the gate wants its test green in the newest evidence from then on.

```sh
devflow config set review.attack sensitive
devflow config set review.attack '{"run":"per-item","model":"large"}'
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
- The targets in force reach checks and readers only as
  `DEVFLOW_SECURITY_TARGETS`. A PoC run recorded against any other target is
  refused.

### What it never does

- Send a request to a third party's host, or to a cloud's metadata service.
- Work around a model's refusal: no retry with another prompt, and no weaker
  model in its place.
- Publish anything: findings stay in the run's files until the person acts.

## A retro of code in production

A range already merged can be reviewed for security alone: `review` with
`base`, `head`, `mode: "retro"` and `axes: ["security"]`. Only the security
reviewer reads it. The exploit tests that prove its findings are written to a
vault, a folder in devflow's cache outside the repository, and its report
says each finding confirmed, not confirmed or not run, with where its exploit
is. An attack on a range (`attack` with `base` and `head`, no item) keeps its
run and exploits in the same vault. `devflow attack promote <range>
<hypothesis>` copies one exploit into the repository at its own path, refusing
a path that leads out of it, and devflow refuses a vault that resolves inside
the checkout.

## How to read the results

Each PoC run the session records has a `result`:

| Result | Means | Effect |
|---|---|---|
| `confirmed` | the exploit test failed as the finding said | holds the item when its severity is in `block_on`; its test must then stay green |
| `refuted` | the PoC ran and the hole is not there | holds nothing |
| `not_run` | the PoC could not run here, with why (no target, a destructive step) | followed up, holds nothing |

An attack finding with no recorded run, its description starting
`unconfirmed:`, is followed up as well. A retro review (`mode: retro`, a range
already in production) is never held: what would have held it is
`follow_up`, and each medium or worse defect carries `impact`, the read-only
query that shows what it touched since the deploy.

## Cost

The attack runs on a large model and reads more than a reviewer. In the first
real runs, one attack reading of a medium-sized diff took about 5 to 10
minutes and US$ 2 to 5, about one and a half times the security reviewer on
the same diff. `per-item` pays that on every re-review, so `sensitive` or
`release` is the usual choice. `devflow status` says what the newest review
spent by stage and model. With the attack stage, `stages.attack.budget`
(`run_usd`, `month_usd`) caps it, and `devflow status --attack` adds up what
its runs cost and confirmed.

## What the attack knows of your project

With the attack stage, a project gives the attack its own context in two
files of devflow's folder. `threat-model.md` lists the assets, the untrusted
inputs, the trust boundaries and their controls; each attack reads it and
proposes its update as a diff, which you take or leave.
`reviewers/devflow-security.overlay.md` adds the project's context to the
security persona: it comes after the persona's rules and cannot remove one.
`devflow persona show devflow-security` prints what a reader reads, and each
run's context names the persona and the overlay by their digests.

## Payload repertoire

devflow ships generic cases by attack class: SSRF, ReDoS, path traversal, SQL
and NoSQL injection, XXE, deserialization and prompt injection. Each case is a neutral input
and what safe code does with it. Its hosts are loopback, private or reserved
names on port 1, never a cloud's metadata address, and it names no real
project or person. `devflow payloads table <class> --runner
jest|vitest|go|pytest` prints a test table with a `check` function you fill
in for the code under test. `stages.attack.regression: [ssrf, redos]` gives
those classes' cases to every attack. A case an attack proposes stays in its
report until you keep it with `devflow payloads add <item> <case>` on a
terminal, in `payloads/<class>.json` of devflow's folder.

The prompt-injection table tests the code that builds a model's messages,
with no model called. Each case is text a user, a tool or a document wrote.
You fill in `build`, which gives the text to your message builder and returns
the messages it built. The table fails when the text became a system,
developer or assistant message, or when a tool's output reached the model
outside its tool role or tool_result block. Whether a tool that writes asks
the person first, and how a delimiter is escaped, is left to the security
review.

## Where exploits run

With the attack stage, set `stages.attack.test` to the command that runs one
exploit test (it gets the test's path as `$DEVFLOW_EXPLOIT`), and devflow runs
each exploit itself in a throwaway worktree of HEAD: in bwrap with a network
namespace of its own, or in docker with no network and the image
`stages.attack.image` names, as your own user. Each exploit gets a worktree
of its own, dropped whole after it ran. The checkout is out of reach there,
only the throwaway copy is written, and time, CPU and memory are capped:
docker caps the container's memory, CPUs and process count; bwrap hides
`/run` and your home folder (showing back only the project's dependency
folders and the toolchains on your `PATH`, read-only), and its CPU and
memory caps hold per process, with no cap on how many it starts. Where neither
sandbox works (bwrap needs unprivileged user namespaces; docker needs the
image), or the command is not set, the exploit stays `tried` with the reason,
and the session runs it.

## Limits today

- **A headless reader cannot run its own PoCs.** Reviewers, the attack's
  included, may only read files and run git's reading commands, so every
  exploit test is written by the attack and run by the session, which then
  records it with `verified`.
- **`verified` is accepted for a critical or high, or for an attack finding.**
  A confirmed medium found by a reviewer has no place to record its PoC.
- **A retro review without an item asks for every axis,** so a security-only
  look at a range still waits on spec and standards.
- **devflow does not sandbox the agent's own shell.** It gives the targets in
  force and asks that nothing else be reached, but a command an agent runs
  runs with your permissions: see [SECURITY.md](../SECURITY.md).
