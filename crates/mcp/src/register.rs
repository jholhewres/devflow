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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Claude,
    Codex,
    Gemini,
    Cursor,
    OpenCode,
    VsCode,
}

pub const ALL: [Tool; 6] = [
    Tool::Claude,
    Tool::Codex,
    Tool::Gemini,
    Tool::Cursor,
    Tool::OpenCode,
    Tool::VsCode,
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
        Machine {
            home,
            config,
            mac: cfg!(target_os = "macos"),
            has: Box::new(|program| on_path(program).is_some()),
            ask: Box::new(|argv| {
                let out = Command::new(argv[0]).args(&argv[1..]).output().ok()?;
                out.status
                    .success()
                    .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
            }),
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

    /// Whether the tool is installed here.
    pub fn found(&self, tool: Tool) -> bool {
        match tool {
            Tool::Claude => (self.has)("claude"),
            Tool::Codex => (self.has)("codex"),
            Tool::Gemini => (self.has)("gemini"),
            Tool::Cursor => (self.has)("cursor-agent") || self.home.join(".cursor").is_dir(),
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
            steps
        }
        Tool::Codex => match (machine.ask)(&["codex", "mcp", "get", NAME]) {
            Some(_) => vec![Step::Done(
                "codex already has the devflow server".to_owned(),
            )],
            None => vec![run(&["codex", "mcp", "add", NAME, "--", bin, "mcp"])],
        },
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
        Tool::Cursor => vec![Step::Put {
            file: machine.home.join(".cursor/mcp.json"),
            under: "mcpServers",
            value: json!({ "command": bin, "args": ["mcp"] }),
        }],
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
    }
}

/// What taking devflow out of `tool` takes.
pub fn unregister(tool: Tool, machine: &Machine) -> Vec<Step> {
    match tool {
        Tool::Claude => vec![
            run(&["claude", "plugin", "uninstall", "devflow@devflow"]),
            run(&["claude", "plugin", "marketplace", "remove", NAME]),
        ],
        Tool::Codex => vec![run(&["codex", "mcp", "remove", NAME])],
        Tool::Gemini => vec![run(&["gemini", "extensions", "uninstall", NAME])],
        Tool::Cursor => vec![Step::Drop {
            file: machine.home.join(".cursor/mcp.json"),
            under: "mcpServers",
        }],
        Tool::OpenCode => vec![Step::Drop {
            file: machine.config.join("opencode/opencode.json"),
            under: "mcp",
        }],
        Tool::VsCode => vec![Step::Drop {
            file: machine.vscode_config(),
            under: "servers",
        }],
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
