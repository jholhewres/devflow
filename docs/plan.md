# Plan

stagegate is devpit's Devflow made to run on its own: a library, a `stagegate`
command line and an MCP server over stdio, so any agent CLI or IDE can use it
without devpit. devpit keeps Devflow by consuming these crates through a thin
adapter. [extraction-map.md](extraction-map.md) lists what moves and why.

## Target architecture

```
crates/
  core     the engine: config, flow, layers, pinning, detect, setup, brief,
           plan, criteria, evidence, findings, review packet, gate, stage,
           decisions (no provider), publish drafts, skills, embedded assets;
           the traits WorkItems, Runner, ReviewAgent, Judge, Forge
  runner   the checks' runner and the report parsers
  agents   Claude Code, Codex, Gemini CLI, Cursor and OpenCode: headless
           review and hooks
  mcp      the MCP server over stdio, on the core
  cli      the `stagegate` binary
assets/    skills, personas, schemas, rubrics, publish templates
```

- **Configuration and state live in the user's repository**: `stagegate.yaml`
  at the root or in `.stagegate/`, runs in `.stagegate/runs/` (ignored by
  git). Outside it only the personal layer (`$XDG_CONFIG_HOME/stagegate/`) and
  the team layers' cache (`$XDG_CACHE_HOME/stagegate/`).
- **No dependency on devpit.** devpit depends on stagegate.
- **A project already on devpit's Devflow is read where it is**
  (`.devpit/devflow/devflow.yaml`); `stagegate migrate` moves it when the
  person asks.
- Linux and macOS first. Windows after the runner has a story for process
  groups there.

## Phases

| # | Phase | Delivers | Done when |
|---|---|---|---|
| 0 | Scaffold | repository, license, CI, docs, `stagegate --help`, `stagegate status` | CI green |
| 1 | Core | `crates/devflow` and `flow/` copied into `core` and `assets`; devpit's crates replaced by `fsguard`, `git`, `env` and `criteria` modules and types of its own; paths renamed with the devpit layout still read | devpit's own Devflow tests pass here with no `devpit_*` |
| 2 | Runner | `runner` ported from devpit's steps runner and report parsers | the evidence tests are green |
| 3 | CLI | `init`, `status`, `set`, `enable`, `skill`, `brief`, `plan`, `check`, `review`, `gate`, `stage`, `publish`, `next`, `hooks`, `mcp`, `migrate`; `WorkItems` on files; the person's confirmations on a terminal | the whole flow on a sample repository without devpit |
| 4 | MCP | `stagegate mcp` with the twelve tools and `next`; the skills as prompts and resources | Claude Code and Codex use it from `.mcp.json` |
| 5 | Adapters | headless review and hooks for the five CLIs; `gh`, `glab` and Bitbucket for publish | review and gate work in at least three CLIs |
| 6 | devpit switches | devpit's `crates/devflow` becomes an adapter (path, then git, then crates.io dependency); `devpit_devflow_*` proxy to the core; the desktop shell loses its duplicated logic | devpit's `make test` green with the same behaviour |
| 7 | Release | a guide per CLI and IDE, migration notes, changelog, `cargo install stagegate`, release binaries | 0.1.0 |

## History

devpit's Devflow history is **not** carried over with `git filter-repo`. It is
41 commits over 12 days, each one spanning devpit's desktop shell, contract,
frontend and MCP server; filtered down to the crate they would describe changes
that are not there, and phase 1 rewrites every import anyway. The `NOTICE`
records the commit the code comes from, and devpit's history stays public.

## Risks

- **Two copies drifting** between phases 1 and 6. Logic changes to devpit's
  `crates/devflow` either wait or are ported the same day.
- **The configuration's path.** Both layouts are read, the new one wins, and
  nothing is moved without `migrate`.
- **Tool names and the skills' text** name devpit about 90 times. The core uses
  neutral names; devpit's adapter keeps its own.
- **The person's click becomes a terminal prompt**, and an agent with a shell
  can answer a prompt. A real terminal is required and the limit is documented.
- **A team layer's commands are somebody else's code**: pinned commit, and a
  confirmation of the exact command, as in devpit.
- **Decisions without a provider**: off by default; a provider is opt-in and,
  as in devpit, never sent the diff.

## For people already on devpit

Nothing changes until phase 6. After it: the same tools, the same window, the
same home; `.devpit/devflow/` keeps being read. Running `stagegate` in the same
repository reads the same configuration.
