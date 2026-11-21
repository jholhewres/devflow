//! `devflow doctor`: what this machine and this project need for devflow,
//! each said ok or not with what to do.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use devflow_engine::folder::State;
use devflow_engine::Ask;

use crate::consent::Consent;
use crate::credentials;
use crate::decisions::settings::Settings;
use crate::project::Project;
use crate::register::{self, Machine, UserServer};

/// One finding: whether it is fine, and what it says.
pub struct Said {
    pub ok: bool,
    /// Not fine, but nothing devflow needs.
    pub optional: bool,
    pub what: String,
}

fn ok(what: impl Into<String>) -> Said {
    Said {
        ok: true,
        optional: false,
        what: what.into(),
    }
}

fn bad(what: impl Into<String>) -> Said {
    Said {
        ok: false,
        optional: false,
        what: what.into(),
    }
}

fn maybe(what: impl Into<String>) -> Said {
    Said {
        ok: false,
        optional: true,
        what: what.into(),
    }
}

/// Every finding, in the order a person fixes them. `session` is the command
/// line of each process this one runs under, nearest first: a Claude Code
/// session's among them says which plugins it loads.
pub fn findings(
    root: &Path,
    machine: &Machine,
    consent: &Consent,
    bin: &str,
    session: &[Vec<String>],
) -> Vec<Said> {
    let mut said = Vec::new();
    match register::on_path(register::NAME) {
        Some(found) => said.push(ok(format!("devflow is on PATH at {}", found.display()))),
        None => said.push(bad(
            "devflow is not on PATH: add its folder (install.sh puts it in ~/.local/bin) to your shell's profile",
        )),
    }
    if register::on_path("git").is_some() {
        said.push(ok("git is installed"));
    } else {
        said.push(bad(
            "git is not installed: reviews and the gate read the repository with it",
        ));
    }
    let found: Vec<register::Tool> = register::ALL
        .into_iter()
        .filter(|tool| machine.found(*tool))
        .collect();
    if found.is_empty() {
        said.push(bad(
            "no agent CLI or IDE found: install one, then `devflow register`",
        ));
    }
    let registered: Vec<(register::Tool, bool)> = found
        .iter()
        .map(|tool| (*tool, register::registered(*tool, bin, machine)))
        .collect();
    // One tool is enough; the others are the person's to want.
    let any = registered.iter().any(|(_, yes)| *yes);
    let server = register::user_server(&machine.claude);
    for (tool, yes) in registered {
        let what = match (tool, &server) {
            (register::Tool::Claude, UserServer::Missing) => format!(
                "claude: devflow's server is not in your user config, so a session has it only \
                 through the devflow plugin, and one that loads another plugin named devflow \
                 (`claude --plugin-dir`, as devpit starts its sessions) has no devflow tools: \
                 `{CLAUDE_FIX}` puts it there, and the plugin's copy steps aside"
            ),
            (register::Tool::Claude, UserServer::Other(runs)) => format!(
                "claude: your user config's devflow server runs `{runs}`, not `devflow mcp`, so \
                 Claude Code keeps it beside the plugin's and each devflow tool shows twice: \
                 `{CLAUDE_FIX}` sets it to `devflow mcp`"
            ),
            _ => format!(
                "{}: devflow is not registered: `devflow register --tools={}`",
                tool.id(),
                tool.id()
            ),
        };
        said.push(match (yes, any) {
            (true, _) if tool == register::Tool::Claude => ok(
                "claude: devflow is registered, its server in your user config, so every \
                 session has it",
            ),
            (true, _) => ok(format!("{}: devflow is registered", tool.id())),
            (false, true) => maybe(what),
            (false, false) => bad(what),
        });
    }
    if let Some(plugin) = shadowing(session) {
        said.push(match server {
            UserServer::Same => ok(format!(
                "this Claude Code session loads {}, another plugin named devflow, which hides \
                 the devflow plugin; devflow's server reaches it from your user config (a \
                 session started before it was put there needs starting again)",
                plugin.display()
            )),
            _ => bad(format!(
                "this Claude Code session loads {}, another plugin named devflow, which hides \
                 the devflow plugin: no devflow server here, so no `attack` and no \
                 devflow-attack skill: `{CLAUDE_FIX}`, then start the session again",
                plugin.display()
            )),
        });
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    let reviewers: Vec<&str> = devflow_engine::agents::Cli::ALL
        .iter()
        .filter(|cli| devflow_engine::env::found_on(&path, cli.program().as_ref()).is_some())
        .map(|cli| cli.id())
        .collect();
    if reviewers.is_empty() {
        said.push(maybe(
            "no reviewer CLI (claude, codex, cursor-agent, gemini, opencode): the session reviews each persona itself",
        ));
    } else {
        said.push(ok(format!(
            "reviewers can run headless on: {}",
            reviewers.join(", ")
        )));
    }
    if register::on_path("gh").is_some() {
        said.push(ok("gh is installed, for pull request reviews"));
    } else {
        said.push(maybe(
            "gh is not installed: reviewing and publishing a pull request need it",
        ));
    }
    if let Some(state) = devflow_engine::home::state_dir() {
        said.extend(update_lock(&state.join(crate::update::LOCK)));
    }
    said.extend(project(root, consent));
    said.extend(decisions());
    said
}

/// devflow's update lock, when one is there: held by an update running now,
/// or left by one that stopped, which the next update takes over.
fn update_lock(lock: &Path) -> Option<Said> {
    if !lock.exists() {
        return None;
    }
    Some(if crate::update::left_behind(lock) {
        maybe(format!(
            "{} was left by an update that stopped: the next `devflow update` takes it over",
            lock.display()
        ))
    } else {
        ok(format!("an update is running now ({})", lock.display()))
    })
}

/// The one command that puts devflow's server where every Claude Code
/// session finds it.
pub const CLAUDE_FIX: &str = "devflow register --tools=claude";

/// The plugin a Claude Code session in `session` loads with `--plugin-dir`
/// that is named devflow but serves no devflow MCP server: it hides the
/// devflow plugin, whose server and skills the session then lacks. A
/// checkout of devflow loaded that way serves its server, and hides nothing.
pub fn shadowing(session: &[Vec<String>]) -> Option<PathBuf> {
    session
        .iter()
        .flat_map(|argv| plugin_dirs(argv))
        .find(|dir| hides_devflow(dir))
}

/// The folders a command line names with `--plugin-dir`, either way of
/// writing it.
fn plugin_dirs(argv: &[String]) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let mut words = argv.iter();
    while let Some(word) = words.next() {
        if let Some(dir) = word.strip_prefix("--plugin-dir=") {
            dirs.push(PathBuf::from(dir));
        } else if word == "--plugin-dir" {
            dirs.extend(words.next().map(PathBuf::from));
        }
    }
    dirs
}

fn hides_devflow(dir: &Path) -> bool {
    let json = |file: PathBuf| -> Option<serde_json::Value> {
        serde_json::from_str(&std::fs::read_to_string(file).ok()?).ok()
    };
    let Some(manifest) = json(dir.join(".claude-plugin/plugin.json")) else {
        return false;
    };
    if manifest.get("name").and_then(serde_json::Value::as_str) != Some(register::NAME) {
        return false;
    }
    let in_manifest = manifest
        .get("mcpServers")
        .and_then(|servers| servers.get(register::NAME))
        .is_some();
    let in_file = json(dir.join(".mcp.json")).is_some_and(|file| {
        file.get("mcpServers")
            .unwrap_or(&file)
            .get(register::NAME)
            .is_some()
    });
    !in_manifest && !in_file
}

/// The most processes walked up from this one.
const MOST_ANCESTORS: usize = 32;

/// The command line of each process this one runs under, nearest first.
#[cfg(unix)]
pub fn ancestors() -> Vec<Vec<String>> {
    let mut lines = Vec::new();
    let mut pid = std::os::unix::process::parent_id();
    while pid > 1 && lines.len() < MOST_ANCESTORS {
        let Some((argv, parent)) = process(pid) else {
            break;
        };
        lines.push(argv);
        pid = parent;
    }
    lines
}

#[cfg(not(unix))]
pub fn ancestors() -> Vec<Vec<String>> {
    Vec::new()
}

/// A process's command line and its parent.
#[cfg(target_os = "linux")]
fn process(pid: u32) -> Option<(Vec<String>, u32)> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let argv = raw
        .split(|byte| *byte == 0)
        .filter(|word| !word.is_empty())
        .map(|word| String::from_utf8_lossy(word).into_owned())
        .collect();
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let parent = status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))?
        .trim()
        .parse()
        .ok()?;
    Some((argv, parent))
}

/// A process's command line, split on spaces, and its parent.
#[cfg(all(unix, not(target_os = "linux")))]
fn process(pid: u32) -> Option<(Vec<String>, u32)> {
    let said = register::asked_within(
        &[
            "ps",
            "-o",
            "ppid=",
            "-o",
            "command=",
            "-p",
            &pid.to_string(),
        ],
        std::time::Duration::from_secs(5),
    )?;
    let (parent, command) = said.trim().split_once(char::is_whitespace)?;
    Some((
        command.split_whitespace().map(str::to_owned).collect(),
        parent.trim().parse().ok()?,
    ))
}

fn project(root: &Path, consent: &Consent) -> Vec<Said> {
    let project = Project::at(root);
    let mut said = Vec::new();
    let layout = project.layout();
    match project.read() {
        State::Missing => {
            said.push(maybe(format!(
                "{}: no devflow.yaml: `devflow setup` makes one",
                project.root.display()
            )));
            return said;
        }
        State::Invalid(_, invalid) => {
            said.push(bad(format!("{} is invalid: {invalid}", layout.file)));
            return said;
        }
        State::Valid(_, config) => {
            said.push(ok(format!("{} reads", layout.file)));
            if layout.dir == devflow_engine::folder::LEGACY {
                said.push(ok("the project is on devpit's layout, read where it is"));
            }
            let how = format!(
                "an MCP client that can ask (elicitation) asks you when its `attack` tool needs \
                 it; else `{}` in a terminal sets the attack up too, or `devflow config set \
                 enabled true`",
                crate::ready::COMMAND
            );
            match (config.enabled, consent.made(&project.root, Ask::Enable)) {
                (true, true) => said.push(ok("devflow is on here")),
                (true, false) => said.push(bad(format!(
                    "devflow is not on here: {} says `enabled: true` (devpit's switch, or the \
                     file's), but devflow's own switch for this project is kept on this machine, \
                     and it is off: {how}",
                    layout.file
                ))),
                (false, _) => said.push(bad(format!(
                    "devflow is not on here: {} says `enabled: false`: {how}",
                    layout.file
                ))),
            }
            said.extend(consented(&project.root, consent));
            let filled =
                crate::ready::prefilled(&project.root, consent, config.stages.attack.budget);
            if !filled.is_empty() {
                said.push(maybe(format!(
                    "{}: stages.attack.budget ({}) was filled in by the attack's question of \
                     devflow 0.6.2 or 0.6.3, never chosen, so it no longer holds the attack: \
                     `devflow config set stages.attack.budget null` takes it out",
                    layout.file,
                    crate::ready::described(filled)
                )));
            }
            let path = std::env::var_os("PATH").unwrap_or_default();
            if config.stages_on().contains(&"attack") {
                said.push(sandbox(&config.stages.attack, &path));
            }
            for check in config.stages.execution.every_check() {
                match devflow_engine::available::why_not(&project.root, &path, &check.run) {
                    None => said.push(ok(format!("check `{}` can run", check.name))),
                    Some(why) => said.push(bad(format!("check `{}`: {why}", check.name))),
                }
            }
            if config.decisions.use_ && credentials::source().is_none() {
                said.push(bad(
                    "devflow.yaml uses Decisions but no key is set: `devflow jev setup`",
                ));
            }
        }
    }
    let ignore = project.root.join(layout.dir).join(".gitignore");
    let ignored = std::fs::read_to_string(&ignore)
        .is_ok_and(|text| text.lines().any(|line| line.trim() == "runs/"));
    if ignored {
        said.push(ok("runs are kept out of git"));
    } else {
        said.push(bad(format!(
            "{} does not ignore runs/: add the line, or run `devflow setup` again",
            ignore.display()
        )));
    }
    said
}

/// The person's yeses kept for the project, how and when each came, and the
/// parts of the attack's question that are not asked again: why a session
/// is not asked what it was asked before.
fn consented(root: &Path, consent: &Consent) -> Vec<Said> {
    let mut said = Vec::new();
    let given: Vec<String> = consent
        .given(root)
        .iter()
        .map(|one| {
            let how = match one.how {
                crate::consent::How::Terminal => "on a terminal",
                crate::consent::How::Elicitation => "to the client's question",
            };
            format!("{} {how} at {} (for {})", one.what, one.at, one.asked_for)
        })
        .collect();
    if !given.is_empty() {
        said.push(ok(format!("the person's yeses here: {}", given.join("; "))));
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in consent.answered(root) {
        let part = if part.starts_with("targets:") {
            "targets"
        } else {
            match part.as_str() {
                "test" => "test",
                "image" => "image",
                _ => continue,
            }
        };
        if !parts.contains(&part) {
            parts.push(part);
        }
    }
    if !parts.is_empty() {
        said.push(ok(format!(
            "the attack's question does not ask again for: {} (`{}` asks it all again, on a terminal)",
            parts.join(", "),
            crate::ready::COMMAND
        )));
    }
    said
}

/// Where the attack's exploits run here, and why bwrap does not when
/// `auto` fell back to docker.
fn sandbox(attack: &devflow_engine::config::Attack, path: &std::ffi::OsStr) -> Said {
    use devflow_engine::config::SandboxChoice;
    use devflow_engine::sandbox::{self, Kind};
    let choice = attack.sandbox.unwrap_or(SandboxChoice::Auto);
    match sandbox::found(choice, attack.image.as_deref(), path) {
        Ok(found) => {
            let mut what = format!("the attack's exploits run in {}", found.kind.word());
            if choice == SandboxChoice::Auto && found.kind == Kind::Docker {
                if let Err(why) = sandbox::found(SandboxChoice::Bwrap, None, path) {
                    what.push_str(&format!(", not bwrap: {why}"));
                }
            }
            // What 0.6.4 to 0.6.6 set for PHP: that image has no mbstring.
            let php = attack.test.as_deref().is_some_and(|test| {
                test.contains("vendor/bin/phpunit") || test.contains("vendor/bin/pest")
            });
            if found.kind == Kind::Docker && php && found.image.as_deref() == Some("php:8") {
                return maybe(format!(
                    "{what}, in php:8: that image has no mbstring, and PHPUnit and Pest need it: \
                     `devflow config set stages.attack.image composer:2`"
                ));
            }
            ok(what)
        }
        Err(why) => maybe(format!(
            "the attack has no sandbox here ({why}): the session runs each exploit itself"
        )),
    }
}

fn decisions() -> Vec<Said> {
    let settings = Settings::of_user();
    let mut said = Vec::new();
    if let Err(why) = settings.checked() {
        said.push(bad(format!(
            "Decisions settings: {why}: `devflow jev setup`"
        )));
    }
    match credentials::source() {
        Some(source) => said.push(ok(format!(
            "Decisions: {} at {}, key from {source} (`devflow jev test` checks it)",
            settings.model(),
            settings.base()
        ))),
        None => said.push(maybe(
            "Decisions is off: no key (`devflow jev setup` to use Jev)",
        )),
    }
    said
}

pub fn run(root: &Path) -> ExitCode {
    let machine = Machine::here();
    let bin = std::env::current_exe()
        .and_then(|path| path.canonicalize().or(Ok(path)))
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| register::NAME.to_owned());
    let said = findings(root, &machine, &Consent::of_user(), &bin, &ancestors());
    let mut failed = false;
    for one in &said {
        let mark = match (one.ok, one.optional) {
            (true, _) => "ok  ",
            (false, true) => "--  ",
            (false, false) => {
                failed = true;
                "FIX "
            }
        };
        println!("{mark}{}", one.what);
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
#[path = "doctor_tests.rs"]
mod tests;
