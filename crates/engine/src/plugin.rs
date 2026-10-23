//! Devflow for each agent CLI: the hooks that hold a turn at the gate and
//! give a session its card, and the stages' skills.
//!
//! devpit writes these and hands them to the sessions it starts in a
//! project where Devflow is on — Claude Code's as a plugin folder on the
//! launch line, Codex's as hooks on its own launch line with their trust —
//! and never into a CLI's own settings: a session started anywhere else
//! never hears of them. The MCP server the hooks call is the one the same
//! launch line already brings (`devpit`); a second copy in the plugin would
//! list every tool twice.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::skills;

/// The plugin's name: Claude Code's skills are `/devflow:<stage>`.
pub const NAME: &str = "devflow";
/// The server devpit's launch line names, whose tool the stop hooks call.
pub const SERVER: &str = "devpit";
/// The gate's tool.
pub const GATE_TOOL: &str = "devpit_devflow_gate";
/// A stop may wait on Decisions; the gate answers well inside this.
pub const GATE_WAITS: u64 = 30;
/// The card's context is a question to the app on loopback.
pub const CONTEXT_WAITS: u64 = 10;

/// The CLIs Devflow has hooks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cli {
    Claude,
    Codex,
}

impl Cli {
    pub fn of(agent: &str) -> Option<Cli> {
        match agent {
            "claude" => Some(Cli::Claude),
            "codex" => Some(Cli::Codex),
            _ => None,
        }
    }

    pub fn word(self) -> &'static str {
        match self {
            Cli::Claude => "claude",
            Cli::Codex => "codex",
        }
    }
}

/// The line the session-start hook runs: devpit's own CLI asking the app
/// for the card. A command, because a tool call is skipped at launch,
/// before the CLI has connected its MCP servers.
pub fn context_command(exe: &str, cli: Cli) -> String {
    format!("\"{exe}\" agent devflow-context --agent {}", cli.word())
}

fn gate(input: Value) -> Value {
    json!({
        "type": "mcp_tool",
        "server": SERVER,
        "tool": GATE_TOOL,
        "input": input,
        "timeout": GATE_WAITS,
    })
}

/// Each event and its one handler. The event is written in, not taken from
/// the payload: a placeholder a CLI did not fill must not decide which.
fn handlers(exe: &str, cli: Cli) -> [(&'static str, Value); 3] {
    [
        (
            "Stop",
            gate(json!({
                "event": "Stop",
                "session": "${session_id}",
                "stop_hook_active": "${stop_hook_active}",
            })),
        ),
        (
            "SubagentStop",
            gate(json!({
                "event": "SubagentStop",
                "session": "${session_id}",
                "stop_hook_active": "${stop_hook_active}",
                "agent": "${agent_id}",
                "transcript": "${agent_transcript_path}",
            })),
        ),
        (
            "SessionStart",
            json!({
                "type": "command",
                "command": context_command(exe, cli),
                "timeout": CONTEXT_WAITS,
            }),
        ),
    ]
}

/// The hooks, in the `hooks.json` shape both CLIs read.
pub fn hooks(exe: &str, cli: Cli) -> Value {
    let mut events = Map::new();
    for (event, handler) in handlers(exe, cli) {
        events.insert(event.to_owned(), json!([{ "hooks": [handler] }]));
    }
    json!({ "description": "Devflow's gate and card context, from devpit", "hooks": events })
}

/// A skill that sends the agent to the project's own: devpit resolves the
/// project's, the person's or its built-in one, so the plugin stays one
/// folder for every project.
fn pointer(name: &str, skill: &str, description: &str) -> String {
    format!(
        "---\nname: {name}\ndescription: {description}\n---\n\n\
         Call devpit's `devpit_devflow_skill` tool with `{{ \"name\": \"{skill}\" }}` and follow the \
         skill it returns: it is this project's own when the project has one. When devpit does not \
         offer that tool, read the resource `{}` from the devpit server instead.\n",
        skills::uri(skill)
    )
}

/// One description on one line, as frontmatter takes it.
fn one_line(text: &str) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    serde_json::to_string(&flat).unwrap_or_default()
}

/// Claude Code's plugin folder, by path inside it: loaded with
/// `--plugin-dir`, for that session only. Skills are `/devflow:<stage>`.
pub fn claude(exe: &str) -> Vec<(String, String)> {
    let manifest = json!({
        "name": NAME,
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Devflow's gate, card context and stage skills, from devpit",
        "author": { "name": "devpit" },
    });
    let mut files = vec![
        (".claude-plugin/plugin.json".to_owned(), pretty(&manifest)),
        (
            "hooks/hooks.json".to_owned(),
            pretty(&hooks(exe, Cli::Claude)),
        ),
    ];
    for (skill, stage, description) in skills::described() {
        let short = stage.unwrap_or("setup");
        files.push((
            format!("skills/{short}/SKILL.md"),
            pointer(short, skill, &one_line(&description)),
        ));
    }
    files
}

/// The marketplace Codex adds the plugin from.
pub const MARKETPLACE: &str = "devpit";

/// Codex's plugin, as a local marketplace folder holding it: the skills as
/// `$devflow-<stage>`, since Codex reads no MCP prompts. Codex installs a
/// plugin into every session it starts, so its hooks are not in it: they
/// ride devpit's own launch line instead ([`codex_flags`]). Installing it is
/// `codex plugin marketplace add <folder>`, the person's to run.
pub fn codex(_exe: &str) -> Vec<(String, String)> {
    let manifest = json!({
        "name": NAME,
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Devflow's stage skills, from devpit",
        "author": { "name": "devpit" },
    });
    let market = json!({
        "name": MARKETPLACE,
        "plugins": [{
            "name": NAME,
            "source": { "source": "local", "path": format!("./{NAME}") },
            "policy": { "installation": "AVAILABLE", "authentication": "ON_INSTALL" },
            "category": "Productivity",
        }],
    });
    let mut files = vec![
        (
            ".agents/plugins/marketplace.json".to_owned(),
            pretty(&market),
        ),
        (format!("{NAME}/plugin.json"), pretty(&manifest)),
    ];
    for (skill, _, description) in skills::described() {
        files.push((
            format!("{NAME}/skills/{skill}/SKILL.md"),
            pointer(skill, skill, &one_line(&description)),
        ));
    }
    files
}

fn pretty(value: &Value) -> String {
    format!(
        "{}\n",
        serde_json::to_string_pretty(value).unwrap_or_default()
    )
}

/// Where Codex files hooks given with `-c`, which its trust is keyed by.
pub const SESSION_FLAGS: &str = "/<session-flags>/config.toml";

/// Codex's name for an event in its trust keys.
fn label(event: &str) -> &'static str {
    match event {
        "Stop" => "stop",
        "SubagentStop" => "subagent_stop",
        _ => "session_start",
    }
}

/// `value` with every object's keys in order, at every level, whatever
/// order the map type keeps.
fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            Value::Object(
                keys.into_iter()
                    .map(|key| (key.clone(), sorted(&map[key])))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

/// The hash Codex trusts a hook by: SHA-256 of the hook as it normalizes it
/// — the event, the matcher, the one handler with its timeout and `async`
/// filled in — as JSON with its keys sorted.
pub fn trust_hash(event: &str, handler: &Value) -> String {
    let mut normal = handler.clone();
    if handler["type"] == "command" {
        normal["async"] = handler.get("async").cloned().unwrap_or(json!(false));
    }
    let identity = json!({ "event_name": label(event), "hooks": [normal] });
    let text = serde_json::to_string(&sorted(&identity)).unwrap_or_default();
    format!("sha256:{:x}", Sha256::digest(text.as_bytes()))
}

/// A value as TOML, inline: what `-c` reads after its `=`.
fn toml(value: &Value) -> String {
    match value {
        Value::Object(map) => format!(
            "{{{}}}",
            map.iter()
                .map(|(key, value)| format!("{}={}", toml_key(key), toml(value)))
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Array(items) => {
            format!("[{}]", items.iter().map(toml).collect::<Vec<_>>().join(","))
        }
        // A JSON string's escapes are all TOML's too.
        Value::String(text) => serde_json::to_string(text).unwrap_or_default(),
        Value::Null => "\"\"".to_owned(),
        other => other.to_string(),
    }
}

fn toml_key(key: &str) -> String {
    let bare = !key.is_empty()
        && key
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-');
    if bare {
        key.to_owned()
    } else {
        serde_json::to_string(key).unwrap_or_default()
    }
}

/// The hooks for one Codex session, and the trust for exactly them: Codex
/// runs no hook nobody trusted, and trust given on the launch line lasts
/// as long as that session. `None` for a binary path that a shell line
/// cannot carry.
pub fn codex_flags(exe: &str) -> Option<String> {
    if exe.contains(['\'', '"', '\\']) {
        return None;
    }
    let mut events = Map::new();
    let mut state = Map::new();
    for (event, handler) in handlers(exe, Cli::Codex) {
        state.insert(
            format!("{SESSION_FLAGS}:{}:0:0", label(event)),
            json!({ "trusted_hash": trust_hash(event, &handler) }),
        );
        events.insert(event.to_owned(), json!([{ "hooks": [handler] }]));
    }
    events.insert("state".to_owned(), Value::Object(state));
    let value = toml(&Value::Object(events));
    // Quoted whole for the shell this line is typed into.
    (!value.contains('\'')).then(|| format!("-c 'hooks={value}'"))
}

#[cfg(test)]
#[path = "plugin_tests.rs"]
mod tests;
