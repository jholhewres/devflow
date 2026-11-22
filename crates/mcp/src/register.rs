//! Registering devflow with each agent CLI and IDE found on this machine,
//! and taking it out again.
//!
//! A CLI with a command for it is asked through that command; a JSON config
//! is edited in place, its order kept, after a copy of it beside it. A config
//! that is not plain JSON (comments, a `.jsonc`) is never rewritten: the
//! person is told what to add.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Map, Value};

/// The GitHub repository the plugin, marketplace and extension come from.
pub const REPO: &str = "jholhewres/devflow";
/// The server's name in every config.
pub const NAME: &str = "devflow";
/// How Claude Code runs devflow's server: as the plugin's manifest says, so
/// the same entry in the person's user config makes Claude Code keep one of
/// the two (it leaves out a plugin's server that runs what a configured one
/// runs), and a session that loads another plugin named devflow, which
/// hides devflow's, still has the server.
pub const CLAUDE_SERVER: [&str; 2] = ["devflow", "mcp"];

/// How long Codex waits on one of devflow's tools: a review or the checks
/// may take most of an hour, and Codex otherwise gives up on a call in
/// minutes.
pub const CODEX_TOOL_TIMEOUT: &str = "3600";
/// How many times in a row Cursor sends a turn back for the gate.
const CURSOR_LOOP_LIMIT: u64 = 5;
/// The rule Cursor reads in each project.
pub const CURSOR_RULE: &str = include_str!("../../../integrations/cursor/rules/devflow.mdc");
/// What Codex (and Cursor) read in a project's AGENTS.md.
pub const AGENTS_SECTION: &str = include_str!("../../../integrations/codex/AGENTS.md");
/// Where devflow's section of a project's AGENTS.md starts and ends.
const BLOCK_START: &str = "<!-- devflow -->";
const BLOCK_END: &str = "<!-- /devflow -->";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Claude,
    Codex,
    Gemini,
    Cursor,
    OpenCode,
    VsCode,
    Antigravity,
    Windsurf,
}

pub const ALL: [Tool; 8] = [
    Tool::Claude,
    Tool::Codex,
    Tool::Gemini,
    Tool::Cursor,
    Tool::OpenCode,
    Tool::VsCode,
    Tool::Antigravity,
    Tool::Windsurf,
];

impl Tool {
    pub fn id(self) -> &'static str {
        match self {
            Tool::Claude => "claude",
            Tool::Codex => "codex",
            Tool::Gemini => "gemini",
            Tool::Cursor => "cursor",
            Tool::OpenCode => "opencode",
            Tool::VsCode => "vscode",
            Tool::Antigravity => "antigravity",
            Tool::Windsurf => "windsurf",
        }
    }

    pub fn of(id: &str) -> Option<Tool> {
        ALL.into_iter().find(|tool| tool.id() == id)
    }
}

/// A read-only command's success and stdout.
pub type Asker = Box<dyn Fn(&[&str]) -> Option<String>>;

/// Where this machine keeps things, so tests can point it elsewhere.
pub struct Machine {
    pub home: PathBuf,
    pub config: PathBuf,
    /// Where Claude Code keeps `.claude.json`, its user-scope MCP servers
    /// among it: `$CLAUDE_CONFIG_DIR`, else the home folder.
    pub claude: PathBuf,
    /// Where Codex keeps its config and hooks: `$CODEX_HOME`, else `~/.codex`.
    pub codex: PathBuf,
    /// The project a registration also writes into (Cursor's rule,
    /// AGENTS.md): the one it runs in, once devflow is set up there.
    pub project: Option<PathBuf>,
    pub mac: bool,
    /// Whether a program is on `PATH`.
    pub has: Box<dyn Fn(&str) -> bool>,
    pub ask: Asker,
}

impl Machine {
    pub fn here() -> Machine {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default();
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .unwrap_or_else(|| home.join(".config"));
        let claude = std::env::var_os("CLAUDE_CONFIG_DIR")
            .filter(|dir| !dir.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home.clone());
        let codex = std::env::var_os("CODEX_HOME")
            .filter(|dir| !dir.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".codex"));
        Machine {
            home,
            config,
            claude,
            codex,
            project: None,
            mac: cfg!(target_os = "macos"),
            has: Box::new(|program| on_path(program).is_some()),
            ask: Box::new(|argv| asked_within(argv, ASK_WAIT)),
        }
    }

    fn vscode_config(&self) -> PathBuf {
        if self.mac {
            self.home
                .join("Library/Application Support/Code/User/mcp.json")
        } else {
            self.config.join("Code/User/mcp.json")
        }
    }

    /// Windsurf's MCP config: Devin Desktop's, the app Windsurf became,
    /// where it is here; else the one Windsurf itself reads.
    fn windsurf_config(&self) -> PathBuf {
        let devin = self.config.join("devin");
        if (self.has)("devin-desktop") || (self.has)("devin") || devin.is_dir() {
            devin.join("mcp_config.json")
        } else {
            self.home.join(".codeium/windsurf/mcp_config.json")
        }
    }

    /// Whether the tool is installed here: its program on `PATH`, or a file
    /// it writes, never a folder alone, which an uninstall leaves behind.
    pub fn found(&self, tool: Tool) -> bool {
        let file = |at: PathBuf| at.is_file();
        match tool {
            Tool::Claude => (self.has)("claude"),
            Tool::Codex => (self.has)("codex"),
            Tool::Gemini => (self.has)("gemini"),
            Tool::Cursor => {
                (self.has)("cursor-agent")
                    || (self.has)("cursor")
                    || ["mcp.json", "hooks.json", "cli-config.json"]
                        .iter()
                        .any(|name| file(self.home.join(".cursor").join(name)))
            }
            Tool::Antigravity => {
                (self.has)("agy")
                    || (self.has)("antigravity")
                    || file(self.home.join(".gemini/config/mcp_config.json"))
                    || file(self.home.join(".gemini/antigravity/installation_id"))
                    || file(self.home.join(".gemini/antigravity-cli/settings.json"))
            }
            Tool::Windsurf => {
                ["windsurf", "surf", "devin-desktop", "devin"]
                    .iter()
                    .any(|program| (self.has)(program))
                    || file(self.home.join(".codeium/windsurf/mcp_config.json"))
                    || file(self.config.join("devin/mcp_config.json"))
            }
            Tool::OpenCode => (self.has)("opencode") || self.config.join("opencode").is_dir(),
            Tool::VsCode => {
                (self.has)("code") || self.vscode_config().parent().is_some_and(Path::is_dir)
            }
        }
    }
}

/// One thing to do for a tool.
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    /// Run this command.
    Run(Vec<String>),
    /// Set `key` under the object at `under` in a JSON file to `value`.
    Put {
        file: PathBuf,
        under: &'static str,
        value: Value,
    },
    /// Remove `key` under `under`.
    Drop { file: PathBuf, under: &'static str },
    /// Already as it should be.
    Done(String),
    /// Cannot be done here; what to do by hand.
    Manual(String),
    /// Add devflow's hook to the list at `path` in a JSON hooks file, `top`
    /// set first when it is missing; `note` says what the tool still asks.
    Hook {
        file: PathBuf,
        path: [&'static str; 2],
        entry: Value,
        top: Option<(&'static str, Value)>,
        note: &'static str,
    },
    /// Take devflow's hooks out of that list.
    Unhook {
        file: PathBuf,
        path: [&'static str; 2],
    },
    /// Set `key = value` under a TOML table's header, one line added; a key
    /// the person set there is left as it is.
    Toml {
        file: PathBuf,
        table: &'static str,
        key: &'static str,
        value: &'static str,
    },
    /// A file of devflow's own, written when it is missing.
    Own { file: PathBuf, text: &'static str },
    /// That file taken out, only while it is as devflow wrote it.
    Disown { file: PathBuf, text: &'static str },
    /// devflow's section in a text file the project keeps, between markers.
    Block { file: PathBuf, text: &'static str },
    /// That section taken out.
    Unblock { file: PathBuf },
}

fn run(argv: &[&str]) -> Step {
    Step::Run(argv.iter().map(|arg| (*arg).to_owned()).collect())
}

/// What registering devflow with `tool` takes. `bin` is the installed
/// binary, named whole where a config is read without the shell's `PATH`.
pub fn register(tool: Tool, bin: &str, machine: &Machine) -> Vec<Step> {
    match tool {
        Tool::Claude => {
            let markets = (machine.ask)(&["claude", "plugin", "marketplace", "list"]);
            let plugins = (machine.ask)(&["claude", "plugin", "list"]);
            let mut steps = Vec::new();
            if markets.as_deref().is_some_and(|said| said.contains(NAME)) {
                steps.push(Step::Done("the devflow marketplace is added".to_owned()));
            } else {
                steps.push(run(&["claude", "plugin", "marketplace", "add", REPO]));
            }
            if plugins
                .as_deref()
                .is_some_and(|said| said.contains("devflow@devflow"))
            {
                steps.push(Step::Done("the devflow plugin is installed".to_owned()));
            } else {
                steps.push(run(&["claude", "plugin", "install", "devflow@devflow"]));
            }
            steps.extend(claude_server(&user_server(&machine.claude)));
            steps
        }
        Tool::Codex => {
            let mut steps = match (machine.ask)(&["codex", "mcp", "get", NAME]) {
                Some(_) => vec![Step::Done(
                    "codex already has the devflow server".to_owned(),
                )],
                None => vec![run(&["codex", "mcp", "add", NAME, "--", bin, "mcp"])],
            };
            steps.push(Step::Toml {
                file: machine.codex.join("config.toml"),
                table: "mcp_servers.devflow",
                key: "tool_timeout_sec",
                value: CODEX_TOOL_TIMEOUT,
            });
            steps.push(Step::Hook {
                file: machine.codex.join("hooks.json"),
                path: ["hooks", "Stop"],
                entry: json!({ "hooks": [{ "type": "command",
                    "command": format!("{bin} hook stop --agent codex") }] }),
                top: None,
                note: "Codex runs it once you trust it in its /hooks",
            });
            if let Some(project) = &machine.project {
                steps.push(Step::Block {
                    file: project.join("AGENTS.md"),
                    text: AGENTS_SECTION,
                });
            }
            steps
        }
        Tool::Gemini => {
            let listed = (machine.ask)(&["gemini", "extensions", "list"]);
            if listed.as_deref().is_some_and(|said| said.contains(NAME)) {
                vec![Step::Done("the devflow extension is installed".to_owned())]
            } else {
                vec![Step::Run(vec![
                    "gemini".to_owned(),
                    "extensions".to_owned(),
                    "install".to_owned(),
                    format!("https://github.com/{REPO}"),
                    "--consent".to_owned(),
                ])]
            }
        }
        Tool::Cursor => vec![
            Step::Put {
                file: machine.home.join(".cursor/mcp.json"),
                under: "mcpServers",
                value: json!({ "command": bin, "args": ["mcp"] }),
            },
            Step::Hook {
                file: machine.home.join(".cursor/hooks.json"),
                path: ["hooks", "stop"],
                entry: json!({ "command": format!("{bin} hook stop --agent cursor"),
                    "loop_limit": CURSOR_LOOP_LIMIT }),
                top: Some(("version", json!(1))),
                note: "",
            },
            match &machine.project {
                Some(project) => Step::Own {
                    file: project.join(".cursor/rules/devflow.mdc"),
                    text: CURSOR_RULE,
                },
                None => Step::Done(
                    "Cursor's rule is a project's: `devflow register --tools=cursor` in a project devflow is set up in writes .cursor/rules/devflow.mdc".to_owned(),
                ),
            },
        ],
        Tool::OpenCode => {
            let dir = machine.config.join("opencode");
            if !dir.join("opencode.json").exists() && dir.join("opencode.jsonc").exists() {
                return vec![Step::Manual(format!(
                    "add to {}: \"mcp\": {{ \"devflow\": {{ \"type\": \"local\", \"command\": [\"{bin}\", \"mcp\"], \"enabled\": true }} }}",
                    dir.join("opencode.jsonc").display()
                ))];
            }
            vec![Step::Put {
                file: dir.join("opencode.json"),
                under: "mcp",
                value: json!({ "type": "local", "command": [bin, "mcp"], "enabled": true }),
            }]
        }
        Tool::VsCode => vec![Step::Put {
            file: machine.vscode_config(),
            under: "servers",
            value: json!({ "type": "stdio", "command": bin, "args": ["mcp"] }),
        }],
        Tool::Antigravity => vec![Step::Put {
            file: machine.home.join(".gemini/config/mcp_config.json"),
            under: "mcpServers",
            value: json!({ "command": bin, "args": ["mcp"] }),
        }],
        Tool::Windsurf => vec![Step::Put {
            file: machine.windsurf_config(),
            under: "mcpServers",
            value: json!({ "command": bin, "args": ["mcp"] }),
        }],
    }
}

/// Whether devflow's gate hook is in `tool`'s hooks file as `bin` runs it:
/// `None` for a tool devflow gives no such hook.
pub fn hook_installed(tool: Tool, bin: &str, machine: &Machine) -> Option<bool> {
    register(tool, bin, machine)
        .iter()
        .find(|step| matches!(step, Step::Hook { .. }))
        .map(done)
}

/// Whether a step is already as it should be here.
fn done(step: &Step) -> bool {
    match step {
        Step::Done(_) => true,
        Step::Put { file, under, value } => std::fs::read_to_string(file)
            .ok()
            .is_some_and(|text| put(Some(&text), under, value) == Ok(None)),
        Step::Hook {
            file,
            path,
            entry,
            top,
            ..
        } => read(file)
            .ok()
            .flatten()
            .is_some_and(|text| hook_put(Some(&text), *path, entry, top.as_ref()) == Ok(None)),
        Step::Toml {
            file,
            table,
            key,
            value,
        } => read(file)
            .ok()
            .flatten()
            .is_some_and(|text| toml_set(&text, table, key, value) == Ok(None)),
        Step::Own { file, text } => read(file).ok().flatten().as_deref() == Some(*text),
        Step::Block { file, text } => read(file)
            .ok()
            .flatten()
            .is_some_and(|said| block_put(Some(&said), text).is_none()),
        Step::Run(_)
        | Step::Drop { .. }
        | Step::Manual(_)
        | Step::Unhook { .. }
        | Step::Disown { .. }
        | Step::Unblock { .. } => false,
    }
}

/// Whether devflow is registered with `tool` as `bin`: every step already
/// done, and every config already holding devflow's entry.
pub fn registered(tool: Tool, bin: &str, machine: &Machine) -> bool {
    register(tool, bin, machine).iter().all(done)
}

/// What taking devflow out of `tool` takes.
pub fn unregister(tool: Tool, machine: &Machine) -> Vec<Step> {
    match tool {
        Tool::Claude => {
            let mut steps = Vec::new();
            if user_server(&machine.claude) != UserServer::Missing {
                steps.push(run(&["claude", "mcp", "remove", "--scope", "user", NAME]));
            }
            steps.push(run(&["claude", "plugin", "uninstall", "devflow@devflow"]));
            steps.push(run(&["claude", "plugin", "marketplace", "remove", NAME]));
            steps
        }
        Tool::Codex => {
            let mut steps = vec![
                run(&["codex", "mcp", "remove", NAME]),
                Step::Unhook {
                    file: machine.codex.join("hooks.json"),
                    path: ["hooks", "Stop"],
                },
            ];
            if let Some(project) = &machine.project {
                steps.push(Step::Unblock {
                    file: project.join("AGENTS.md"),
                });
            }
            steps
        }
        Tool::Gemini => vec![run(&["gemini", "extensions", "uninstall", NAME])],
        Tool::Cursor => {
            let mut steps = vec![
                Step::Drop {
                    file: machine.home.join(".cursor/mcp.json"),
                    under: "mcpServers",
                },
                Step::Unhook {
                    file: machine.home.join(".cursor/hooks.json"),
                    path: ["hooks", "stop"],
                },
            ];
            if let Some(project) = &machine.project {
                steps.push(Step::Disown {
                    file: project.join(".cursor/rules/devflow.mdc"),
                    text: CURSOR_RULE,
                });
            }
            steps
        }
        Tool::OpenCode => vec![Step::Drop {
            file: machine.config.join("opencode/opencode.json"),
            under: "mcp",
        }],
        Tool::VsCode => vec![Step::Drop {
            file: machine.vscode_config(),
            under: "servers",
        }],
        Tool::Antigravity => vec![Step::Drop {
            file: machine.home.join(".gemini/config/mcp_config.json"),
            under: "mcpServers",
        }],
        Tool::Windsurf => vec![Step::Drop {
            file: machine.windsurf_config(),
            under: "mcpServers",
        }],
    }
}

/// devflow's server in Claude Code's user config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserServer {
    /// It runs `devflow mcp`, as the plugin's does.
    Same,
    Missing,
    /// It runs something else, which Claude Code keeps beside the plugin's
    /// server, so each tool shows twice: what it runs.
    Other(String),
}

/// The most of `.claude.json` read: Claude Code keeps each project's
/// history in it, so it is no small config.
const MOST_CLAUDE_JSON: u64 = 64 * 1024 * 1024;

/// devflow's server in the `.claude.json` under `dir`, Claude Code's user
/// scope. A file that cannot be read as JSON holds none.
pub fn user_server(dir: &Path) -> UserServer {
    let file = dir.join(".claude.json");
    let text = std::fs::metadata(&file)
        .ok()
        .filter(|meta| meta.len() <= MOST_CLAUDE_JSON)
        .and_then(|_| std::fs::read_to_string(&file).ok());
    let Some(doc) = text.and_then(|text| serde_json::from_str::<Value>(&text).ok()) else {
        return UserServer::Missing;
    };
    let Some(entry) = doc.get("mcpServers").and_then(|servers| servers.get(NAME)) else {
        return UserServer::Missing;
    };
    let stdio = entry
        .get("type")
        .is_none_or(|kind| kind.as_str() == Some("stdio"));
    let command = entry.get("command").and_then(Value::as_str);
    let args: Vec<&str> = entry
        .get("args")
        .and_then(Value::as_array)
        .map(|args| args.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    match command.filter(|_| stdio) {
        Some(command) if command == CLAUDE_SERVER[0] && args == CLAUDE_SERVER[1..] => {
            UserServer::Same
        }
        Some(command) => UserServer::Other(
            std::iter::once(command)
                .chain(args)
                .collect::<Vec<_>>()
                .join(" "),
        ),
        None => UserServer::Other(match entry.get("type").and_then(Value::as_str) {
            Some(kind) => format!("a {kind} server"),
            None => "no command".to_owned(),
        }),
    }
}

/// What putting devflow's server in Claude Code's user config takes, from
/// what is there now. The binary is named bare, as the plugin names it:
/// whole, it would run something else to Claude Code, which keeps both.
pub fn claude_server(now: &UserServer) -> Vec<Step> {
    let mut add = vec!["claude", "mcp", "add", "--scope", "user", NAME, "--"];
    add.extend(CLAUDE_SERVER);
    match now {
        UserServer::Same => vec![Step::Done(
            "devflow's server is in Claude Code's user config: every session has it".to_owned(),
        )],
        UserServer::Missing => vec![run(&add)],
        UserServer::Other(_) => vec![
            run(&["claude", "mcp", "remove", "--scope", "user", NAME]),
            run(&add),
        ],
    }
}

/// A JSON config with devflow's entry set: `None` when it already is. A file
/// that is not a JSON object is refused, never replaced.
pub fn put(text: Option<&str>, under: &str, value: &Value) -> Result<Option<String>, String> {
    let mut doc = parsed(text)?;
    let entries = doc
        .entry(under)
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(entries) = entries.as_object_mut() else {
        return Err(format!("`{under}` is not an object"));
    };
    if entries.get(NAME) == Some(value) {
        return Ok(None);
    }
    entries.insert(NAME.to_owned(), value.clone());
    Ok(Some(pretty(&Value::Object(doc))))
}

/// A JSON config without devflow's entry: `None` when it has none.
pub fn drop(text: Option<&str>, under: &str) -> Result<Option<String>, String> {
    let Some(text) = text else { return Ok(None) };
    let mut doc = parsed(Some(text))?;
    let removed = doc
        .get_mut(under)
        .and_then(Value::as_object_mut)
        .and_then(|entries| entries.shift_remove(NAME));
    Ok(removed.map(|_| pretty(&Value::Object(doc))))
}

/// Whether a hook entry is devflow's: it runs `devflow hook stop`.
fn ours(entry: &Value) -> bool {
    match entry {
        Value::String(said) => said.contains(" hook stop --agent "),
        Value::Array(list) => list.iter().any(ours),
        Value::Object(fields) => fields.values().any(ours),
        _ => false,
    }
}

/// A JSON hooks file with devflow's `entry` in the list at `path`, and
/// `top` set when missing: `None` when it already is. An older entry of
/// devflow's is replaced; the person's own are kept as they are.
pub fn hook_put(
    text: Option<&str>,
    path: [&str; 2],
    entry: &Value,
    top: Option<&(&str, Value)>,
) -> Result<Option<String>, String> {
    let before = Value::Object(parsed(text)?);
    let mut doc = parsed(text)?;
    if let Some((key, value)) = top {
        doc.entry(*key).or_insert_with(|| value.clone());
    }
    let hooks = doc
        .entry(path[0])
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| format!("`{}` is not an object", path[0]))?;
    let list = hooks
        .entry(path[1])
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| format!("`{}.{}` is not a list", path[0], path[1]))?;
    if !list.contains(entry) {
        list.retain(|had| !ours(had));
        list.push(entry.clone());
    }
    let after = Value::Object(doc);
    Ok((after != before).then(|| pretty(&after)))
}

/// A JSON hooks file without devflow's hooks in the list at `path`: `None`
/// when it has none. A list left empty goes too.
pub fn hook_drop(text: Option<&str>, path: [&str; 2]) -> Result<Option<String>, String> {
    let Some(text) = text else { return Ok(None) };
    let mut doc = parsed(Some(text))?;
    let Some(hooks) = doc.get_mut(path[0]).and_then(Value::as_object_mut) else {
        return Ok(None);
    };
    let Some(list) = hooks.get_mut(path[1]).and_then(Value::as_array_mut) else {
        return Ok(None);
    };
    let had = list.len();
    list.retain(|one| !ours(one));
    if list.len() == had {
        return Ok(None);
    }
    if list.is_empty() {
        hooks.shift_remove(path[1]);
    }
    Ok(Some(pretty(&Value::Object(doc))))
}

/// A TOML file with `key = value` under `[table]`: `None` when the table
/// already sets the key (to anything: the person's own value stands). The
/// line goes right under the table's header, the rest kept as written.
pub fn toml_set(text: &str, table: &str, key: &str, value: &str) -> Result<Option<String>, String> {
    let header = format!("[{table}]");
    let lines: Vec<&str> = text.lines().collect();
    let at = lines
        .iter()
        .position(|line| line.trim() == header)
        .ok_or_else(|| format!("it has no {header}"))?;
    let set = lines[at + 1..]
        .iter()
        .take_while(|line| !line.trim_start().starts_with('['))
        .any(|line| {
            line.trim_start()
                .strip_prefix(key)
                .is_some_and(|rest| rest.trim_start().starts_with('='))
        });
    if set {
        return Ok(None);
    }
    let mut out: Vec<String> = lines.iter().map(|line| (*line).to_owned()).collect();
    out.insert(at + 1, format!("{key} = {value}"));
    Ok(Some(out.join("\n") + "\n"))
}

/// devflow's section, between its markers.
fn block_of(text: &str) -> String {
    format!("{BLOCK_START}\n{}\n{BLOCK_END}", text.trim_end())
}

/// A text file with devflow's section as `text` says it: `None` when it
/// already is. Added at its end when missing, replaced where it is when not.
pub fn block_put(said: Option<&str>, text: &str) -> Option<String> {
    let block = block_of(text);
    let said = said.unwrap_or_default();
    match (said.find(BLOCK_START), said.find(BLOCK_END)) {
        (Some(start), Some(end)) if start < end => {
            let end = end + BLOCK_END.len();
            (said[start..end] != block)
                .then(|| format!("{}{block}{}", &said[..start], &said[end..]))
        }
        _ if said.trim().is_empty() => Some(format!("{block}\n")),
        _ => Some(format!("{}\n\n{block}\n", said.trim_end())),
    }
}

/// A text file without devflow's section: `None` when it has none.
pub fn block_drop(said: &str) -> Option<String> {
    let start = said.find(BLOCK_START)?;
    let end = said.find(BLOCK_END).filter(|end| *end > start)? + BLOCK_END.len();
    let before = said[..start].trim_end();
    let after = said[end..].trim_start_matches('\n');
    Some(match (before.is_empty(), after.is_empty()) {
        (true, _) => after.to_owned(),
        (false, true) => format!("{before}\n"),
        (false, false) => format!("{before}\n\n{after}"),
    })
}

fn parsed(text: Option<&str>) -> Result<Map<String, Value>, String> {
    match text.map(str::trim) {
        None | Some("") => Ok(Map::new()),
        Some(text) => match serde_json::from_str::<Value>(text) {
            Ok(Value::Object(doc)) => Ok(doc),
            Ok(_) => Err("it is not a JSON object".to_owned()),
            Err(_) => Err("it is not plain JSON (comments?), so it is left as it is".to_owned()),
        },
    }
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default() + "\n"
}

/// Carries a step out, or with `dry` only says it. Returns what was said.
pub fn carry(step: &Step, dry: bool) -> Result<String, String> {
    match step {
        Step::Done(said) => Ok(format!("ok: {said}")),
        Step::Manual(said) => Ok(format!("by hand: {said}")),
        Step::Run(argv) => {
            let line = argv.join(" ");
            if dry {
                return Ok(format!("would run: {line}"));
            }
            let status = Command::new(&argv[0])
                .args(&argv[1..])
                .status()
                .map_err(|e| format!("{line}: {e}"))?;
            if status.success() {
                Ok(format!("ran: {line}"))
            } else {
                Err(format!("{line}: exited with {status}"))
            }
        }
        Step::Put { file, under, value } => {
            let text = read(file)?;
            match put(text.as_deref(), under, value)
                .map_err(|why| format!("{}: {why}", file.display()))?
            {
                None => Ok(format!("ok: {} already has devflow", file.display())),
                Some(_) if dry => Ok(format!("would add devflow to {}", file.display())),
                Some(new) => {
                    write(file, text.as_deref(), &new)?;
                    Ok(format!("added devflow to {}", file.display()))
                }
            }
        }
        Step::Drop { file, under } => {
            let text = read(file)?;
            match drop(text.as_deref(), under)
                .map_err(|why| format!("{}: {why}", file.display()))?
            {
                None => Ok(format!("ok: {} has no devflow", file.display())),
                Some(_) if dry => Ok(format!("would remove devflow from {}", file.display())),
                Some(new) => {
                    write(file, text.as_deref(), &new)?;
                    Ok(format!("removed devflow from {}", file.display()))
                }
            }
        }
        Step::Hook {
            file,
            path,
            entry,
            top,
            note,
        } => {
            let text = read(file)?;
            let note = if note.is_empty() {
                String::new()
            } else {
                format!(" ({note})")
            };
            let shown = file.display();
            match hook_put(text.as_deref(), *path, entry, top.as_ref())
                .map_err(|why| format!("{shown}: {why}"))?
            {
                None => Ok(format!("ok: {shown} already has devflow's gate hook{note}")),
                Some(_) if dry => Ok(format!("would add devflow's gate hook to {shown}{note}")),
                Some(new) => {
                    write(file, text.as_deref(), &new)?;
                    Ok(format!("added devflow's gate hook to {shown}{note}"))
                }
            }
        }
        Step::Unhook { file, path } => {
            let text = read(file)?;
            let shown = file.display();
            match hook_drop(text.as_deref(), *path).map_err(|why| format!("{shown}: {why}"))? {
                None => Ok(format!("ok: {shown} has no devflow hook")),
                Some(_) if dry => Ok(format!("would remove devflow's hook from {shown}")),
                Some(new) => {
                    write(file, text.as_deref(), &new)?;
                    Ok(format!("removed devflow's hook from {shown}"))
                }
            }
        }
        Step::Toml {
            file,
            table,
            key,
            value,
        } => {
            let shown = file.display();
            let line = format!("{key} = {value} under [{table}] in {shown}");
            let text = read(file)?.unwrap_or_default();
            match toml_set(&text, table, key, value) {
                Ok(None) => Ok(format!("ok: {shown} already sets {key}")),
                _ if dry => Ok(format!("would set {line}")),
                Ok(Some(new)) => {
                    write(file, Some(&text), &new)?;
                    Ok(format!("set {line}"))
                }
                Err(why) => Err(format!("{shown}: {why}, so {key} is not set")),
            }
        }
        Step::Own { file, text } => {
            let shown = file.display();
            match read(file)? {
                Some(had) if had == *text => Ok(format!("ok: {shown} is devflow's")),
                Some(_) => Ok(format!(
                    "by hand: {shown} is not devflow's as written, so it is left as it is"
                )),
                None if dry => Ok(format!("would write {shown}")),
                None => {
                    write(file, None, text)?;
                    Ok(format!("wrote {shown}"))
                }
            }
        }
        Step::Disown { file, text } => {
            let shown = file.display();
            match read(file)? {
                None => Ok(format!("ok: there is no {shown}")),
                Some(had) if had != *text => Ok(format!(
                    "by hand: {shown} was changed since devflow wrote it, so it is left"
                )),
                Some(_) if dry => Ok(format!("would remove {shown}")),
                Some(_) => {
                    std::fs::remove_file(file).map_err(|e| format!("{shown}: {e}"))?;
                    Ok(format!("removed {shown}"))
                }
            }
        }
        Step::Block { file, text } => {
            let had = read(file)?;
            let shown = file.display();
            match block_put(had.as_deref(), text) {
                None => Ok(format!("ok: {shown} has devflow's section")),
                Some(_) if dry => Ok(format!("would add devflow's section to {shown}")),
                Some(new) => {
                    write(file, had.as_deref(), &new)?;
                    Ok(format!("added devflow's section to {shown}"))
                }
            }
        }
        Step::Unblock { file } => {
            let had = read(file)?;
            let shown = file.display();
            match had.as_deref().and_then(block_drop) {
                None => Ok(format!("ok: {shown} has no devflow section")),
                Some(_) if dry => Ok(format!("would remove devflow's section from {shown}")),
                Some(new) if new.trim().is_empty() => {
                    std::fs::remove_file(file).map_err(|e| format!("{shown}: {e}"))?;
                    Ok(format!(
                        "removed {shown}, which held only devflow's section"
                    ))
                }
                Some(new) => {
                    write(file, had.as_deref(), &new)?;
                    Ok(format!("removed devflow's section from {shown}"))
                }
            }
        }
    }
}

/// A config's text, or `None` when it does not exist. Configs are small: one
/// past a megabyte is not read.
fn read(file: &Path) -> Result<Option<String>, String> {
    match std::fs::metadata(file) {
        Err(_) => Ok(None),
        Ok(meta) if meta.len() > 1024 * 1024 => Err(format!(
            "{}: larger than a config should be",
            file.display()
        )),
        Ok(_) => std::fs::read_to_string(file)
            .map(Some)
            .map_err(|e| format!("{}: {e}", file.display())),
    }
}

/// Writes `new` over `file`, its old text first copied beside it, through a
/// temporary file so a crash never leaves half a config.
fn write(file: &Path, old: Option<&str>, new: &str) -> Result<(), String> {
    let fail = |e: std::io::Error| format!("{}: {e}", file.display());
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent).map_err(fail)?;
    }
    if let Some(old) = old {
        std::fs::write(backup_of(file), old).map_err(fail)?;
    }
    let temp = file.with_extension("devflow-tmp");
    std::fs::write(&temp, new).map_err(fail)?;
    if let Ok(meta) = std::fs::metadata(file) {
        std::fs::set_permissions(&temp, meta.permissions()).map_err(fail)?;
    }
    std::fs::rename(&temp, file).map_err(fail)
}

pub fn backup_of(file: &Path) -> PathBuf {
    let mut name = file.file_name().unwrap_or_default().to_os_string();
    name.push(".devflow-backup");
    file.with_file_name(name)
}

/// Where a program is on `PATH`.
/// How long a query of another CLI may take: a marketplace refresh fetches
/// over git.
const ASK_WAIT: std::time::Duration = std::time::Duration::from_secs(120);

/// What `argv` prints when it succeeds within `wait`, asking nothing: no
/// stdin, and git told never to prompt for a password or a passphrase.
pub fn asked_within(argv: &[&str], wait: std::time::Duration) -> Option<String> {
    use std::io::Read;
    use std::process::Stdio;
    let mut child = Command::new(argv.first()?)
        .args(&argv[1..])
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_SSH_COMMAND", "ssh -o BatchMode=yes")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut out = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut said = String::new();
        let _ = out.read_to_string(&mut said);
        said
    });
    let started = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() < wait => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let said = reader.join().ok()?;
    status.filter(|status| status.success()).map(|_| said)
}

pub fn on_path(program: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(program))
        .find(|path| path.is_file())
}

/// The tools named in `--tools`, or every one found here.
pub fn chosen(named: Option<&str>, machine: &Machine) -> Result<Vec<Tool>, String> {
    match named {
        None => Ok(ALL
            .into_iter()
            .filter(|tool| machine.found(*tool))
            .collect()),
        Some(list) => list
            .split(',')
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(|id| {
                Tool::of(id).ok_or_else(|| {
                    format!("no tool `{id}`: one of {}", ALL.map(Tool::id).join(", "))
                })
            })
            .collect(),
    }
}

#[cfg(test)]
#[path = "register_tests.rs"]
mod tests;
