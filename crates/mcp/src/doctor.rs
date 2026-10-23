//! `devflow doctor`: what this machine and this project need for devflow,
//! each said ok or not with what to do.

use std::path::Path;
use std::process::ExitCode;

use devflow_engine::folder::State;
use devflow_engine::Ask;

use crate::consent::Consent;
use crate::credentials;
use crate::decisions::settings::Settings;
use crate::project::Project;
use crate::register::{self, Machine};

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

/// Every finding, in the order a person fixes them.
pub fn findings(root: &Path, machine: &Machine, consent: &Consent, bin: &str) -> Vec<Said> {
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
    for (tool, yes) in registered {
        let what = format!(
            "{}: devflow is not registered: `devflow register --tools={}`",
            tool.id(),
            tool.id()
        );
        said.push(match (yes, any) {
            (true, _) => ok(format!("{}: devflow is registered", tool.id())),
            (false, true) => maybe(what),
            (false, false) => bad(what),
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
    said.extend(project(root, consent));
    said.extend(decisions());
    said
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
            match (config.enabled, consent.made(&project.root, Ask::Enable)) {
                (true, true) => said.push(ok("devflow is on here")),
                _ => said.push(bad(
                    "devflow is not on here: `devflow config set enabled true`",
                )),
            }
            let path = std::env::var_os("PATH").unwrap_or_default();
            for check in &config.stages.execution.checks {
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
    let said = findings(root, &machine, &Consent::of_user(), &bin);
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
