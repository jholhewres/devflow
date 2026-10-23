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

## Scope

In scope: this repository. Out of scope: findings that require an attacker to
already have local code execution as your user, or write access to the
project's repository, since either one can already run the commands
devflow runs.
