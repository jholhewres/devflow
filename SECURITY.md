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
- With the attack stage on (`stages.attack.run`, `sensitive` unless said;
  `review.attack` is its older name), an attacker **tries to exploit the
  change**: it reads the checkout and writes exploit tests, which devflow
  runs in a sandbox (below) or the session runs, and they may send requests
  to the targets in force, `DEVFLOW_SECURITY_TARGETS`. A target is in force only when
  `security.targets` lists it and the person confirmed it on a terminal
  (`devflow config set security.targets`), and only the project's own
  instances are accepted: loopback, `localhost`, `host.docker.internal`, or a
  docker service's name, each of whose addresses (as a check resolves it,
  search domains included, and as the name alone) is this machine's or a
  private network's.
  A way to make a third party's host a target, or to record a PoC against
  one, is a vulnerability. A compose stack (`security.stack`) is started
  only once the person confirmed it on a terminal, as compose resolves it
  with its images' ids, on a network docker makes internal; a way to start
  one that reaches beyond that network is a vulnerability.
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
- It **runs exploit tests in a sandbox**, when `stages.attack.test` is set
  and bwrap or docker works here. What the sandbox enforces:
  - each exploit runs in a throwaway worktree of the commit it is tried on
    (HEAD, and its base for the proof), dropped after it ran; the checkout
    is never written;
  - no network: bwrap gives it a network namespace of its own, docker runs
    it with none, or attached only to a confirmed stack's internal network;
  - a time limit, and caps on memory and CPU: in docker per container,
    process count included; in bwrap per process, through `prlimit`;
  - in bwrap, `/run` and your home folder are hidden, apart from the
    project's dependency folders and the toolchains on your `PATH`, shown
    back read-only.

  What it does not enforce:
  - it runs as your own user, not a separate one;
  - in bwrap, the rest of the filesystem stays readable: everything outside
    your home folder, `/tmp` and `/run`, the checkout included when it is
    not under your home;
  - bwrap caps no process count, its memory and CPU caps hold per process,
    not for the exploit as a whole, and without `prlimit` on this machine
    there are none;
  - the toolchains shown back are your own, as installed;
  - the docker sandbox needs access to the docker daemon, which is as good
    as root on most machines;
  - a hole in bwrap, docker or the kernel is beyond it.

  Where no sandbox works, the exploit waits for the session, which runs it
  with your permissions. A way for an exploit in the sandbox to write the
  checkout, reach a network it was not given, or outlive its time is a
  vulnerability.
- A **headless reviewer or attacker is held to reading** by its CLI's own
  read-only mode: Claude Code gets no shell at all, Codex runs in its
  read-only sandbox, Cursor in ask mode and Gemini in plan mode, the last two
  as their own settings allow. OpenCode is refused as a headless reader.
- It **does not sandbox the agent's own shell.** The session that builds the
  work, and a reviewer's CLI, run with your permissions and their own
  settings: devflow gives the targets in force and asks that nothing else be
  reached, but it cannot stop a command an agent runs. Keep the reviewer
  CLIs' own permission settings as tight as you keep the session's.
- It **keeps exploits out of the repository**: an attack's exploit code
  stays in its run, beside the item's runs, and a range's in a vault in
  devflow's cache, refused when it would resolve inside the checkout.
  `devflow attack promote` copies one in only when the person asks.

## Scope

In scope: this repository. Out of scope: findings that require an attacker to
already have local code execution as your user, or write access to the
project's repository, since either one can already run the commands
devflow runs.
