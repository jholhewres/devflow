# Integrations

`install.sh` puts `devflow` in `~/.local/bin` and runs `devflow register`,
which does what follows for each tool it finds. Run it again at any time:
it changes only what differs. `devflow register --dry-run` says what it would
do; `devflow unregister` takes devflow out again. A JSON config is copied to
`<file>.devflow-backup` before it is changed, and one with comments is never
rewritten: you are told what to add instead.

| Tool | What gets devflow | What it gets |
|---|---|---|
| Claude Code | `claude plugin marketplace add jholhewres/devflow`, `claude plugin install devflow@devflow` | the MCP server, skills, commands, reviewer agents, the gate's hooks |
| Codex | `codex mcp add devflow -- devflow mcp` | the MCP server; `AGENTS.md` and skills by hand |
| Gemini CLI | `gemini extensions install https://github.com/jholhewres/devflow` | the MCP server and `GEMINI.md` |
| Cursor | `~/.cursor/mcp.json`, `mcpServers.devflow` | the MCP server; a rule by hand |
| OpenCode | `~/.config/opencode/opencode.json`, `mcp.devflow` | the MCP server |
| VS Code (Copilot) | the user's `mcp.json`, `servers.devflow` | the MCP server |

Where a tool has no skills or hooks, the MCP server is enough: the tools say
what comes next.

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
