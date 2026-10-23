//! The person's commands: what only they decide, asked on a real terminal.
//!
//! An agent with a shell could answer a prompt too; the confirmations below
//! need stdin to be a terminal, and none takes a flag that skips them.

use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;

use devflow_engine::folder::State;
use devflow_engine::{preset, proposal, setup, Ask, Proposal};
use serde_json::Value;

use crate::consent::Consent;
use crate::flow::stage::team_command;
use crate::project::Project;

/// Asks `question` on the terminal; only `y` or `yes` is a yes.
pub fn confirmed(question: &str) -> Result<bool, String> {
    if !std::io::stdin().is_terminal() {
        return Err(
            "this needs your yes on a terminal: run it yourself, not through an agent".to_owned(),
        );
    }
    print!("{question} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut said = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut said)
        .map_err(|err| err.to_string())?;
    Ok(matches!(
        said.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn failed(why: &str) -> ExitCode {
    eprintln!("devflow: {why}");
    ExitCode::FAILURE
}

/// `devflow config get [path]`: the configuration that applies, over its
/// layers, or one field of it.
pub fn get(root: &Path, path: Option<&str>) -> ExitCode {
    let project = Project::at(root);
    let config = match project.read() {
        State::Valid(_, config) => config,
        State::Missing => return failed("no devflow.yaml here: `devflow setup` makes one"),
        State::Invalid(_, invalid) => {
            return failed(&format!("devflow.yaml is invalid: {invalid}"))
        }
    };
    let json = config.to_json();
    let value = match path {
        Some(path) => preset::value_at(&json, path).clone(),
        None => json,
    };
    match value {
        Value::Null => failed(&format!(
            "{} is not set",
            path.unwrap_or("the configuration")
        )),
        Value::String(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        other => {
            println!(
                "{}",
                serde_json::to_string_pretty(&other).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
    }
}

/// A value as typed: JSON when it reads as JSON, else the text itself.
pub fn value_of(said: &str) -> Value {
    serde_json::from_str(said).unwrap_or_else(|_| Value::String(said.to_owned()))
}

/// The person's switch a change of `path` to `value` is, if any.
fn ask_of(path: &str, value: &Value) -> Option<Ask> {
    match (path, value) {
        ("enabled", Value::Bool(true)) => Some(Ask::Enable),
        ("decisions.mode", Value::String(mode)) if mode == "enforce" => Some(Ask::Enforce),
        _ => None,
    }
}

/// `devflow config set <path> <value>`: one field of devflow.yaml, shown and
/// written after a yes. Switching devflow on and moving Decisions to
/// enforce are also kept as the person's on this machine.
pub fn set(root: &Path, path: &str, said: &str, consent: &Consent) -> ExitCode {
    match setting(root, path, &value_of(said), consent) {
        Ok(said) => {
            println!("{said}");
            ExitCode::SUCCESS
        }
        Err(why) => failed(&why),
    }
}

fn setting(root: &Path, path: &str, value: &Value, consent: &Consent) -> Result<String, String> {
    let project = Project::at(root);
    let state = project.read();
    let layout = project.layout();
    let ask = ask_of(path, value);
    let proposal: Proposal = match ask {
        Some(ask) => proposal::switched_in(&layout, &state, ask),
        None => proposal::set_in(&layout, &state, path, value),
    }
    .map_err(|why| why.to_string())?;
    devflow_engine::layers::layered(&project.root, &proposal.yaml, &crate::project::home())
        .map_err(|invalid| invalid.to_string())?;
    let before = match &state {
        State::Valid(_, config) => preset::value_at(&config.to_json(), path).clone(),
        _ => Value::Null,
    };
    let after = preset::value_at(&proposal.config.to_json(), path).clone();
    let already = ask.is_some_and(|ask| consent.made(&project.root, ask));
    if proposal.changes.is_empty() && (ask.is_none() || already) {
        return Ok(format!("{path} is already {after}"));
    }
    println!(
        "{} in {}\n  {path}: {before} → {after}",
        layout.file,
        project.root.display()
    );
    let question = match ask {
        Some(Ask::Enable) => "Switch devflow on in this project, on this machine?",
        Some(Ask::Enforce) => "Let Decisions hold work in this project (enforce)?",
        None => "Write it?",
    };
    if !confirmed(question)? {
        return Ok("Nothing was written.".to_owned());
    }
    if !proposal.changes.is_empty() {
        let planned = setup::with_unused(&project.root, &proposal.config, proposal.files.clone());
        setup::write(&project.root, &planned)?;
    }
    if let Some(ask) = ask {
        consent.remember(&project.root, ask, true)?;
    }
    if path == "enabled" && *value == Value::Bool(false) {
        consent.remember(&project.root, Ask::Enable, false)?;
    }
    if path == "decisions.mode" && *value != Value::String("enforce".to_owned()) {
        consent.remember(&project.root, Ask::Enforce, false)?;
    }
    Ok(format!(
        "Written. devflow never commits: {} is yours to commit.",
        layout.file
    ))
}

/// `devflow stage confirm <name>`: a team layer's command for an own stage,
/// shown with its layer and commit, run only after a yes.
pub fn confirm_stage(root: &Path, name: &str, consent: &Consent) -> ExitCode {
    let project = Project::at(root);
    let State::Valid(_, config) = project.read() else {
        return failed("devflow.yaml does not read: `devflow status` says why");
    };
    let (step, gate) = match devflow_engine::stage::gated(&config, name) {
        Ok(found) => found,
        Err(why) => return failed(&why),
    };
    let devflow_engine::config::StageGate::Command(command) = gate else {
        return failed(&format!(
            "the stage `{name}` is gated by a rubric, not a command"
        ));
    };
    let layered = project.layered();
    let Some((team, commit, print)) = team_command(layered.as_ref(), command) else {
        println!("The stage `{name}` runs the project's own command: nothing to confirm.");
        return ExitCode::SUCCESS;
    };
    if consent.command_confirmed(&print) {
        println!("Already confirmed: `{command}` from {team} at {commit}.");
        return ExitCode::SUCCESS;
    }
    println!(
        "The stage `{}` ({}) runs a command from the {team} layer, at commit {commit}:\n\n  {command}\n",
        step.name(),
        step.uses
    );
    match confirmed("Let it run in this project?") {
        Ok(true) => match consent.confirm(&print) {
            Ok(()) => {
                println!("Confirmed for this commit; a new commit asks again.");
                ExitCode::SUCCESS
            }
            Err(why) => failed(&why),
        },
        Ok(false) => {
            println!("Not confirmed: the stage's gate stays waiting.");
            ExitCode::SUCCESS
        }
        Err(why) => failed(&why),
    }
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;
