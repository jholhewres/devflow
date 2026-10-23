# Integrations

`install.sh` puts `devflow` in `~/.local/bin` and runs `devflow register`,
which does what follows for each tool it finds. Run it again at any time:
it changes only what differs. `devflow register --dry-run` says what it would
do; `devflow unregister` takes devflow out again. A JSON config is copied to
`<file>.devflow-backup` before it is changed, and one with comments is never
rewritten: you are told what to add instead.

| Tool | What gets devflow | What it gets |
|---|---|---|
| Claude Code | `claude plugin marketplace add jholhewres/devflow`, `claude plugin install devflow@devflow` | the MCP server; a skill per stage (`/devflow:briefing` … `/devflow:completion`, `/devflow:setup`); the commands `/devflow:status`, `/devflow:items`, `/devflow:next`, `/devflow:gate`, `/devflow:pr`; the reviewer personas as subagents; the Stop, SubagentStop and SessionStart hooks |
| Codex | `codex mcp add devflow -- devflow mcp` | the MCP server; `AGENTS.md` by hand |
| Gemini CLI | `gemini extensions install https://github.com/jholhewres/devflow` | the MCP server and `GEMINI.md` |
| Cursor | `~/.cursor/mcp.json`, `mcpServers.devflow` | the MCP server; a rule by hand |
| OpenCode | `~/.config/opencode/opencode.json`, `mcp.devflow` | the MCP server |
| VS Code (Copilot) | the user's `mcp.json`, `servers.devflow` | the MCP server |

Where a tool has no skills or hooks, the MCP server is enough: its skills are
also MCP prompts and resources (`skill://devflow/<name>/SKILL.md`), and each
tool's answer says what comes next. Without the Stop hook the gate still holds
`finish`; it just cannot hold the end of a turn.

## The flow in any tool

1. `devflow setup` in the project (or ask the agent: it calls `status`, then
   `setup`, and writes only after your yes). Switching devflow on is yours:
   `devflow config set enabled true`, on a terminal.
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
