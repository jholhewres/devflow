# Security

## Reporting a vulnerability

Please report privately through GitHub's
[security advisory form](https://github.com/jholhewres/devflow/security/advisories/new)
rather than a public issue.

Include what you did, what happened, and what you expected. A proof of concept
helps; a working exploit is not required. Expect an acknowledgement within a
week.

## What this software touches

Worth knowing before you run it, and worth keeping in mind when reviewing:

- It **runs commands** from the project's configuration: the checks, a stage's
  gate, and the reviewers' agent CLIs. That is its purpose. Context reaches a
  command only through environment variables, never interpolated into the
  command string; a path that lets untrusted input become shell syntax is a
  vulnerability.
- A **team layer's commands are somebody else's code**. They run only after
  the person confirmed that exact command at that exact pinned commit. A way to
  run one without that confirmation is a vulnerability.
- It **reads and writes files** inside the project. Every path is resolved
  through symlinks and checked against the project's root first; a path that
  escapes the root is a vulnerability even when the link sits inside it.
- It **sends a review's packet** (the diff, the work item and its criteria) to
  the agent CLIs the configuration names, under the person's own accounts.
  Decisions, when switched on, receives findings and criteria and never the
  diff.
- It **posts to a pull request** only after the person said yes to that exact
  draft.
- With `review.attack` on, a reviewer **tries to exploit the change**: it
  reads the checkout, runs its tests, and may send requests to the targets
  in force, `DEVFLOW_SECURITY_TARGETS`. A target is in force only when
  `security.targets` lists it and the person confirmed it on a terminal
  (`devflow config set security.targets`), and only the project's own
  instances are accepted: loopback, `localhost`, `host.docker.internal`, or a
  docker service's name, each of whose addresses (as a check resolves it,
  search domains included, and as the name alone) is this machine's or a
  private network's.
  A way to make a third party's host a target, or to record a PoC against
  one, is a vulnerability.
  What the security reviewer and the attack do, and their limits:
  [docs/security.md](docs/security.md).
- It **reads static analysers' SARIF** from a check's report folder; a
  location outside the project's root is left out unread, and the report is
  kept without the code and file contents it quotes. A rule's message may
  still quote what it matched.
- It **replaces its own binary** with the latest GitHub release when
  `devflow mcp` starts, unless `DEVFLOW_NO_UPDATE=1` or the binary was built
  from a checkout. The release is fetched over https only; its archive must
  match the release's `checksums.txt` and the new binary must run before it
  replaces the old one, kept as `devflow.prev`. The checksum comes from the
  same release, so it guards against a broken download, not a compromised
  release. A way to install anything but a release's own archive is a
  vulnerability.
- It **does not sandbox the agent's own shell.** The session that builds the
  work, and a reviewer's CLI, run with your permissions and their own
  settings: devflow gives the targets in force and asks that nothing else be
  reached, but it cannot stop a command an agent runs. Keep the reviewer
  CLIs' own permission settings as tight as you keep the session's.

## Scope

In scope: this repository. Out of scope: findings that require an attacker to
already have local code execution as your user, or write access to the
project's repository, since either one can already run the commands
devflow runs.
