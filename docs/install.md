# Install and updates

```sh
curl -fsSL https://raw.githubusercontent.com/jholhewres/devflow/main/install.sh | sh
devflow setup
```

`install.sh` checks the release's checksum, puts `devflow` in `~/.local/bin`
and registers it with the agent CLIs and IDEs it finds
([integrations](integrations.md)). Its options:

| Option | Does |
|---|---|
| `--tools=claude,codex,…` | register with these tools only |
| `--version=0.6.1` | install this release instead of the newest |
| `--dry-run` | download and verify, then say what would change |
| `--uninstall` | take devflow out of each tool, and remove the binary |

`devflow setup` writes the project's `devflow.yaml` and switches devflow on,
asking first. `devflow doctor` checks the machine and the project.

## Updates

devflow keeps itself current. Each time an agent CLI starts `devflow mcp`, a
background thread asks GitHub for the latest release and installs a newer
one over the binary:

- the archive must match the release's `checksums.txt`, and the new binary
  must run before it replaces the old one, which is kept as `devflow.prev`;
- the Claude Code plugin is brought to the same version;
- the server answers at once; offline, it logs one line and carries on, and
  the next start runs the new version.

`devflow update` does it now (`--check` only looks, `--json` answers in one
line). `DEVFLOW_NO_UPDATE=1` switches it off, and a build from a checkout
never replaces itself.
