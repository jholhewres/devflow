//! The person's commands: what only they decide, asked on a real terminal.
//!
//! An agent with a shell could answer a prompt too; the confirmations below
//! need stdin to be a terminal, and none takes a flag that skips them.

use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;

use devflow_engine::folder::State;
use devflow_engine::security::Pins;
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
        Some(path) => match preset::find(&json, path) {
            Ok(value) => value.clone(),
            Err(why) => return failed(&why),
        },
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

/// What a change of devflow.yaml is besides its field: one of the person's
/// switches, the targets an attack may reach, or neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Field,
    Switch(Ask),
    Targets,
    Stack,
}

fn kind_of(path: &str, value: &Value) -> Kind {
    match ask_of(path, value) {
        Some(ask) => Kind::Switch(ask),
        None if path == "security.stack" => Kind::Stack,
        None if devflow_engine::security::persons_only(path) => Kind::Targets,
        None => Kind::Field,
    }
}

/// One `config set`: the change shown, asked, written after a yes, and what
/// only the person decides kept on this machine. A switch is kept as made;
/// the targets as the list the person allowed, a shorter one narrowing it.
fn setting(root: &Path, path: &str, value: &Value, consent: &Consent) -> Result<String, String> {
    let project = Project::at(root);
    let state = project.read();
    let layout = project.layout();
    let kind = kind_of(path, value);
    let proposal: Proposal = match kind {
        Kind::Switch(ask) => proposal::switched_in(&layout, &state, ask),
        _ => proposal::set_in(&layout, &state, path, value),
    }
    .map_err(|why| why.to_string())?;
    let layered =
        devflow_engine::layers::layered(&project.root, &proposal.yaml, &crate::project::home())
            .map_err(|invalid| invalid.to_string())?;
    let before = match &state {
        State::Valid(_, config) => preset::value_at(&config.to_json(), path).clone(),
        _ => Value::Null,
    };
    let after = preset::value_at(&proposal.config.to_json(), path).clone();
    let targets = layered.config.security.targets;
    let kept = consent.confirmed_targets(&project.root);
    let pins = consent.pinned(&project.root);
    // Every name resolved once, together: what it is shown with and kept as.
    let found = match kind {
        Kind::Targets => devflow_engine::security::resolved(
            &targets,
            &devflow_engine::security::resolved_here_all,
        ),
        _ => Pins::new(),
    };
    let new = to_confirm(&targets, &kept, &pins, &found);
    // The stack as compose resolves it now: what is shown is what is kept.
    let seen = match kind {
        Kind::Stack => {
            let stack = layered.config.security.stack.clone().unwrap_or_default();
            Some(stack_resolved(&project.root, &stack)?)
        }
        _ => None,
    };
    let already = proposal.changes.is_empty()
        && match kind {
            Kind::Field => true,
            Kind::Switch(ask) => consent.made(&project.root, ask),
            Kind::Targets => new.is_empty() && unconfirmed(&kept, &targets).is_empty(),
            Kind::Stack => {
                let named = layered.config.security.stack.as_deref();
                matches!(
                    (consent.confirmed_stack(&project.root), named, &seen),
                    (Some((file, digest)), Some(named), Some((_, now))) if file == named && digest == *now
                )
            }
        };
    if already {
        return Ok(format!("{path} is already {after}"));
    }
    println!(
        "{} in {}\n  {path}: {before} → {after}",
        layout.file,
        project.root.display()
    );
    let question = match kind {
        Kind::Switch(Ask::Enable) => "Switch devflow on in this project, on this machine?",
        Kind::Switch(Ask::Enforce) => "Let Decisions hold work in this project (enforce)?",
        Kind::Targets if !new.is_empty() => {
            for target in &new {
                let again = unconfirmed(std::slice::from_ref(target), &kept).is_empty();
                let said = if again {
                    "to confirm again"
                } else {
                    "new here"
                };
                println!("  {said}: {}", shown(target, &found));
            }
            "devflow's attack and checks may send requests, exploits included, to these \
             targets. They are this project's own instances, never a third party's. Allow them, \
             on this machine?"
        }
        Kind::Stack => {
            let stack = layered.config.security.stack.clone().unwrap_or_default();
            let (config, digest) = seen.as_ref().ok_or("security.stack names no file")?;
            println!("  compose file: {stack}, as compose resolves it (sha256 {digest})");
            for (name, service) in config["services"].as_object().into_iter().flatten() {
                println!(
                    "    service {name}: {}",
                    service["image"].as_str().unwrap_or("?")
                );
            }
            "devflow's attack will start this compose stack on an internal network, with no \
             published port and no way out, and send exploits to its services. It is this \
             project's own stack. Allow it, on this machine? Any change to what it resolves to \
             asks again."
        }
        _ => "Write it?",
    };
    if !confirmed(question)? {
        return Ok("Nothing was written, and nothing was confirmed.".to_owned());
    }
    if !proposal.changes.is_empty() {
        let planned = setup::with_unused(&project.root, &proposal.config, proposal.files.clone());
        setup::write(&project.root, &planned)?;
    }
    match kind {
        Kind::Switch(ask) => consent.remember(&project.root, ask, true)?,
        Kind::Targets => {
            let pins = pins_after(&targets, &new, &pins, &found);
            consent.confirm_targets(&project.root, &targets, &pins)?;
        }
        Kind::Stack => {
            let stack = layered.config.security.stack.clone().unwrap_or_default();
            let (_, digest) = seen.as_ref().ok_or("security.stack names no file")?;
            consent.confirm_stack(&project.root, Some((&stack, digest)))?;
        }
        Kind::Field => {}
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

/// The stack `file` as compose resolves it, and its digest.
fn stack_resolved(root: &Path, file: &str) -> Result<(Value, String), String> {
    let docker = crate::register::on_path("docker").ok_or("security.stack needs docker")?;
    devflow_engine::stack::resolved(&docker, root, file)
}

/// The targets in `after` not among those `confirmed`, by origin.
pub(crate) fn unconfirmed(after: &[String], confirmed: &[String]) -> Vec<String> {
    use devflow_engine::security::{origins, target};
    let origins = origins(confirmed);
    after
        .iter()
        .filter(|url| target(url).map_or(true, |one| !origins.contains(&one.origin())))
        .cloned()
        .collect()
}

/// The targets of `after` the person is asked to confirm: those not yet
/// confirmed, and each name whose addresses were never kept or that
/// resolves elsewhere now (`found`), so a moved name is shown again.
pub(crate) fn to_confirm(
    after: &[String],
    confirmed: &[String],
    pins: &Pins,
    found: &Pins,
) -> Vec<String> {
    use devflow_engine::security::target;
    let new = unconfirmed(after, confirmed);
    let moved = |url: &String| {
        target(url).is_ok_and(|one| {
            let now = found.get(&one.origin()).map_or(&[][..], Vec::as_slice);
            one.named
                && pins
                    .get(&one.origin())
                    .is_none_or(|then| now.iter().any(|address| !then.contains(address)))
        })
    };
    after
        .iter()
        .filter(|url| new.contains(url) || moved(url))
        .cloned()
        .collect()
}

/// The addresses kept with the yes to `after`: what each name in `shown`
/// resolves to now, and for the rest what was kept before.
pub(crate) fn pins_after(after: &[String], shown: &[String], pins: &Pins, found: &Pins) -> Pins {
    use devflow_engine::security::target;
    after
        .iter()
        .filter_map(|url| {
            target(url)
                .ok()
                .filter(|one| one.named)
                .map(|one| (url, one))
        })
        .filter_map(|(url, one)| {
            let origin = one.origin();
            let from = if shown.contains(url) { found } else { pins };
            from.get(&origin)
                .map(|addresses| (origin, addresses.clone()))
        })
        .collect()
}

/// What a target new to this machine is shown with before the yes: what
/// its name resolves to here (`found`), which is what an attack would reach
/// and what is kept with the yes.
fn shown(url: &str, found: &Pins) -> String {
    use devflow_engine::security::target;
    match target(url) {
        Ok(one) if one.named => {
            let found = found.get(&one.origin()).cloned().unwrap_or_default();
            if found.is_empty() {
                format!("{url} (resolves to nothing here)")
            } else {
                let found: Vec<String> = found.iter().map(ToString::to_string).collect();
                format!("{url} → {}", found.join(", "))
            }
        }
        _ => url.to_owned(),
    }
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
