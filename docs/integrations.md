# Integrations

`install.sh` puts `devflow` in `~/.local/bin` and runs `devflow register`,
which does what follows for each tool it finds. Run it again at any time:
it changes only what differs. `devflow register --dry-run` says what it would
do; `devflow unregister` takes devflow out again. A JSON config is copied to
`<file>.devflow-backup` before it is changed, and one with comments is never
rewritten: you are told what to add instead.

| Tool | What gets devflow | What it gets |
|---|---|---|
| Claude Code | `claude plugin marketplace add jholhewres/devflow`, `claude plugin install devflow@devflow`, `claude mcp add --scope user devflow -- devflow mcp` | the MCP server, in every session ([below](#claude-code-and-another-plugin-named-devflow)); a skill per stage (`/devflow:briefing` … `/devflow:completion`, `/devflow:setup`); the commands `/devflow:status`, `/devflow:items`, `/devflow:next`, `/devflow:gate`, `/devflow:pr`; the reviewer personas as subagents; the Stop, SubagentStop and SessionStart hooks |
| Codex | `codex mcp add devflow -- devflow mcp` | the MCP server; `AGENTS.md` by hand |
| Gemini CLI | `gemini extensions install https://github.com/jholhewres/devflow` | the MCP server and `GEMINI.md` |
| Cursor | `~/.cursor/mcp.json`, `mcpServers.devflow` | the MCP server; a rule by hand |
| OpenCode | `~/.config/opencode/opencode.json`, `mcp.devflow` | the MCP server |
| VS Code (Copilot) | the user's `mcp.json`, `servers.devflow` | the MCP server |

Where a tool has no skills or hooks, the MCP server is enough: its skills are
also MCP prompts and resources (`skill://devflow/<name>/SKILL.md`), and each
tool's answer says what comes next. Without the Stop hook the gate still holds
`finish`; it just cannot hold the end of a turn.

## Claude Code and another plugin named devflow

Claude Code loads one plugin per name. A session started with
`--plugin-dir` pointing at another plugin named `devflow` (devpit starts
its sessions with its own) hides the devflow plugin, and with it the MCP
server, the `attack` tool and the plugin's skills and hooks, without a word.

So `devflow register` also puts the server in Claude Code's user config,
which every session reads whatever plugins it loads. It names the command
exactly as the plugin does, `devflow mcp`: Claude Code leaves out a
plugin's server that runs what a configured one runs, so where the plugin is
loaded too, each tool still shows once (the tools are then
`mcp__devflow__*`, not `mcp__plugin_devflow_devflow__*`). The skills reach
the session through the server: its `skill` tool, prompts and resources
carry every stage's, `devflow-attack` among them. The hooks are left to the
plugin: a host that hides it brings its own gate.

`devflow doctor` says whether the server is in the user config, and, run
inside a Claude Code session, names a plugin loaded with `--plugin-dir` that
hides devflow's. In a session where the plugin brings the server, `status`
tells Claude Code the same and offers, once, to put it there: one question
through the client, done on the person's yes, and a no is kept in
`consent.json` and not asked again. `devflow register --tools=claude` is
the one command for it.

## The flow in any tool

1. `devflow setup` in the project (or ask the agent: it calls `status`, then
   `setup`, and writes only after your yes). Switching devflow on is yours:
   `devflow config set enabled true`, on a terminal, or your yes when the
   `attack` tool asks you through a client with MCP elicitation, which sets
   the attack up in the same question.
2. Ask for the work: the agent briefs it (`brief`, an epic in
   `.devflow/work/`), gathers context, and plans it (`plan`) into items, each
   with its acceptance criteria — made after your yes.
3. Per item: `start`, build it test-first, `evidence` runs the checks with
   each criterion mapped to its tests, `review` has it reviewed headless on
   the reviewer CLIs you have (or by the session, persona by persona), then
   `gate`, then `finish`. `next` names the item that comes after.
4. A pull request on its own: `review` with `pr`, then `publish` after your
   yes to the draft (`/devflow:pr 42` in Claude Code).

## The hooks

The plugin's hooks run `devflow hook stop|subagent-stop|session-start --agent
claude`. At a stop, the gate judges the item `start` named; a turn that ends
while it fails is sent back with what is missing, up to Claude Code's
`CLAUDE_CODE_STOP_HOOK_BLOCK_CAP` times in a row, then let go with a note on
the item. At a session's start, the agent is told its item, the item's
criteria and what still blocks it. Where devflow is off, the hooks say
nothing.

## By hand

The files under [`integrations/`](../integrations) are the same entries, ready
to copy. They name `devflow` and rely on `PATH`; `devflow register` writes the
binary's whole path, since an IDE started from the desktop may not see
`~/.local/bin`.

- **Codex**: [`integrations/codex/config.toml`](../integrations/codex/config.toml)
  into `~/.codex/config.toml`, and
  [`integrations/codex/AGENTS.md`](../integrations/codex/AGENTS.md) into the
  project's `AGENTS.md`.
- **Cursor**: [`integrations/cursor/mcp.json`](../integrations/cursor/mcp.json)
  as `~/.cursor/mcp.json` or the project's `.cursor/mcp.json`, and
  [`integrations/cursor/rules/devflow.mdc`](../integrations/cursor/rules/devflow.mdc)
  into `.cursor/rules/`.
- **OpenCode**: [`integrations/opencode/opencode.json`](../integrations/opencode/opencode.json)
  merged into `~/.config/opencode/opencode.json` or the project's.
- **VS Code**: [`integrations/vscode/mcp.json`](../integrations/vscode/mcp.json)
  as the project's `.vscode/mcp.json`, or through *MCP: Open User
  Configuration*.
- **Any other MCP client**: a stdio server, command `devflow`, argument `mcp`,
  started in the project's directory.
