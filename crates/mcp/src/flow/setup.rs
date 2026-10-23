//! `status`, `setup` and `set`: the project's state with what was detected,
//! a setup previewed and applied, and one field changed. Switching devflow
//! on and moving Decisions to `enforce` are the person's, in a terminal.

use std::path::Path;

use devflow_engine::config::Agent;
use devflow_engine::detect::{self, Cli, Machine};
use devflow_engine::folder::State;
use devflow_engine::preset::{self, Preset};
use devflow_engine::{proposal, setup, Ask, Proposal};
use serde_json::{json, Map, Value};

use super::{offered, Offered};
use crate::project::{self, Project};
use crate::server::Server;

/// The command that switches devflow on, which only the person runs.
pub const ENABLE: &str = "devflow config set enabled true";
/// The command that moves Decisions to enforce.
pub const ENFORCE: &str = "devflow config set decisions.mode enforce";

/// The word `status` says for `state`.
pub fn state_word(state: &State, active: bool) -> &'static str {
    match state {
        State::Missing => "no file",
        State::Invalid(..) => "invalid",
        State::Valid(..) if active => "active",
        State::Valid(..) => "disabled",
    }
}

/// The step `status` says comes next.
pub fn next_step(state: &State, switched_on: bool, active: bool) -> String {
    match state {
        _ if active => "start with `skill` devflow-briefing".to_owned(),
        State::Missing if switched_on => {
            "commit the devflow folder on the default branch: this checkout has no devflow.yaml"
                .to_owned()
        }
        State::Missing => "`setup` previews one".to_owned(),
        State::Invalid(..) => "`set` fixes the field the error names".to_owned(),
        State::Valid(..) => format!("the person runs `{ENABLE}` in a terminal"),
    }
}

pub fn status(server: &Server, _: Value) -> Result<Value, String> {
    let project = server.project();
    Ok(status_of(&project, server))
}

pub fn status_of(project: &Project, server: &Server) -> Value {
    let state = project.read();
    let switched_on = server.consent.made(&project.root, Ask::Enable);
    let active = matches!(offered(&state, switched_on), Offered::Active(_));
    let detected = detect::detected(&project.root, machine(&project.root));
    let layout = project.layout();
    let mut said = json!({
        "state": state_word(&state, active),
        "root": project.root,
        "file": layout.file,
        "folder": layout.dir,
        "yaml": Value::Null,
        "recommended_checks": preset::checks(&detected),
        "open": detect::open(&detected),
        "detected": detected,
        "next": next_step(&state, switched_on, active),
        "note": Value::Null,
    });
    if let Some(layered) = project.layered() {
        said["teams"] = json!(layered.teams);
        said["stages_from"] = json!(layered.stages_from);
    }
    let note = match &state {
        State::Missing if switched_on => Some(
            "The person switched devflow on here, but this checkout has no devflow.yaml: it is \
             on another branch, or was never committed."
                .to_owned(),
        ),
        State::Missing => Some("No devflow.yaml yet: `setup` previews one.".to_owned()),
        State::Invalid(text, invalid) => {
            said["yaml"] = json!(text);
            said["error"] = json!(invalid);
            Some(format!(
                "devflow.yaml is invalid, so the flow's tools stay off: {invalid}."
            ))
        }
        State::Valid(text, config) => {
            said["yaml"] = json!(text);
            said["config"] = config.to_json();
            let unread = devflow_engine::config::unread(text);
            said["unread"] = json!(unread);
            let waiting = (!switched_on).then(|| {
                format!(
                    "devflow is set up here but not switched on: the person runs `{ENABLE}` in a \
                     terminal, which no tool does for them."
                )
            });
            [waiting, unread_note(&unread)]
                .into_iter()
                .flatten()
                .reduce(|one, other| format!("{one} {other}"))
        }
    };
    said["note"] = json!(note);
    said
}

/// The fields a newer devflow wrote, left out rather than refused.
pub fn unread_note(unread: &[devflow_engine::Invalid]) -> Option<String> {
    let named: Vec<String> = unread.iter().map(ToString::to_string).collect();
    (!named.is_empty()).then(|| {
        format!(
            "This devflow does not read {}, and runs without it: a newer version wrote it, or \
             it is misspelled.",
            named.join("; ")
        )
    })
}

/// A change refused when the file it leaves would not read over its layers.
fn layered_as(root: &Path, proposal: &Proposal) -> Result<(), String> {
    devflow_engine::layers::layered(root, &proposal.yaml, &project::home())
        .map(|_| ())
        .map_err(|invalid| format!("{invalid}"))
}

/// Why an apply is a preview again: the setup now is not the one shown.
pub fn unseen(shown: Option<&Proposal>, now: &Proposal) -> Option<String> {
    let Some(shown) = shown else {
        return Some("the person has not seen a preview of this setup".to_owned());
    };
    let changed = now.changed_since(shown)?;
    Some(match changed.is_empty() {
        true => "the files it writes changed since the preview the person saw".to_owned(),
        false => format!(
            "it changed since the preview the person saw ({})",
            changed.join(", ")
        ),
    })
}

/// What a written proposal leaves to the person, said as the commands to run.
fn waiting(proposal: &Proposal, switched_on: bool, after_setup: bool) -> Vec<String> {
    let mut asks = proposal.asks.clone();
    if after_setup && !switched_on && !asks.contains(&Ask::Enable) {
        asks.push(Ask::Enable);
    }
    asks.iter()
        .map(|ask| match ask {
            Ask::Enable => ENABLE.to_owned(),
            Ask::Enforce => ENFORCE.to_owned(),
        })
        .collect()
}

pub fn applied_note(switched_on: bool, waiting: &[String]) -> String {
    let on = if switched_on {
        "devflow is on here.".to_owned()
    } else {
        format!("devflow stays off until the person runs `{ENABLE}` in a terminal.")
    };
    let enforce = if waiting.iter().any(|one| one == ENFORCE) {
        format!(" Decisions stays in shadow until the person runs `{ENFORCE}`.")
    } else {
        String::new()
    };
    format!(
        "Written. devflow never commits: these files are the person's to commit on the default \
         branch, or a worktree started from it finds no setup. {on}{enforce}"
    )
}

pub fn setup(server: &Server, params: Value) -> Result<Value, String> {
    let project = server.project();
    let state = project.read();
    let word = params
        .get("preset")
        .and_then(Value::as_str)
        .unwrap_or(Preset::Recommended.word());
    let preset = Preset::of(word)
        .ok_or_else(|| format!("`{word}` is not a preset: recommended or custom"))?;
    let set: Map<String, Value> = match params.get("set") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(set)) => set.clone(),
        Some(_) => return Err("`set` is an object of dotted path to value".to_owned()),
    };
    let detected = detect::detected(&project.root, machine(&project.root));
    let proposal = proposal::setup_in(&project.layout(), &state, preset, &set, &detected)
        .map_err(|why| why.to_string())?;
    layered_as(&project.root, &proposal)?;
    let asked = params.get("apply").and_then(Value::as_bool) == Some(true);
    let mut shown = server.preview.lock().map_err(|_| "busy".to_owned())?;
    let moved = asked.then(|| unseen(shown.as_ref(), &proposal)).flatten();
    let apply = asked && moved.is_none();
    *shown = (!apply).then(|| proposal.clone());
    drop(shown);
    let checks: Vec<Value> = proposal
        .config
        .stages
        .execution
        .checks
        .iter()
        .map(|check| {
            let script = proposal.scripts.iter().find(|one| one.name == check.name);
            json!({
                "name": check.name,
                "run": check.run,
                "command": script.map(|one| one.command.as_str()),
                "source": script.and_then(|one| one.source.as_deref()),
                "report": check.report,
            })
        })
        .collect();
    let planned = setup::with_unused(&project.root, &proposal.config, proposal.files.clone());
    let files = if apply {
        setup::write(&project.root, &planned)?
    } else {
        setup::preview(&project.root, &planned)
    };
    let switched_on = server.consent.made(&project.root, Ask::Enable);
    let waiting = if apply {
        waiting(&proposal, switched_on, true)
    } else {
        Vec::new()
    };
    Ok(json!({
        "applied": apply,
        "preset": word,
        "yaml": proposal.yaml,
        "checks": checks,
        "files": files,
        "open": detect::open(&detected),
        "unavailable": detected
            .every()
            .filter_map(|(one, kind)| {
                let why = one.unavailable.as_deref()?;
                Some(json!({ "kind": kind, "command": one.command, "source": one.source, "why": why }))
            })
            .collect::<Vec<_>>(),
        "asks": proposal.asks,
        "for_the_person": waiting,
        "note": match (apply, moved) {
            (true, _) => applied_note(switched_on, &waiting),
            (false, Some(why)) => format!(
                "Nothing was written: {why}. This is the setup now: show it, and apply once the \
                 person says yes to it."
            ),
            (false, None) => "Nothing was written. apply: true writes these files, once the \
                person said yes to this preview."
                .to_owned(),
        },
    }))
}

pub fn set(server: &Server, params: Value) -> Result<Value, String> {
    let project = server.project();
    let state = project.read();
    let path = params
        .get("path")
        .and_then(Value::as_str)
        .ok_or("pass the field as a dotted `path`, such as review.block_on")?;
    let value = params
        .get("value")
        .ok_or("pass the new `value` for the field")?;
    let proposal =
        proposal::set_in(&project.layout(), &state, path, value).map_err(|why| why.to_string())?;
    layered_as(&project.root, &proposal)?;
    let apply = params.get("apply").and_then(Value::as_bool) == Some(true);
    let before = match &state {
        State::Valid(_, config) => preset::value_at(&config.to_json(), path).clone(),
        _ => Value::Null,
    };
    let written = apply && !proposal.changes.is_empty();
    let planned = setup::with_unused(&project.root, &proposal.config, proposal.files.clone());
    let files = if written {
        setup::write(&project.root, &planned)?
    } else {
        setup::preview(&project.root, &planned)
    };
    if written && !proposal.config.enabled {
        // Switched off: switching on again is the person's again.
        let _ = server.consent.remember(&project.root, Ask::Enable, false);
    }
    let waiting = if apply {
        waiting(&proposal, true, false)
    } else {
        Vec::new()
    };
    let wrote = match (apply, written) {
        (true, true) => "Written. devflow never commits: the file is the person's to commit.",
        (true, false) => "Nothing was written to the file.",
        (false, _) => "Nothing was written. apply: true writes it, once the person said yes.",
    };
    let asked = if proposal.asks.is_empty() {
        String::new()
    } else {
        format!(
            " Switching devflow on and moving Decisions to enforce are never written by a tool: \
             the person runs `{ENABLE}` or `{ENFORCE}` in a terminal."
        )
    };
    Ok(json!({
        "applied": written,
        "path": path,
        "before": before,
        "after": preset::value_at(&proposal.config.to_json(), path),
        "changes": proposal.changes,
        "yaml": proposal.yaml,
        "laid_out": proposal.laid_out,
        "files": files,
        "asks": proposal.asks,
        "for_the_person": waiting,
        "note": format!("{wrote}{asked}"),
    }))
}

/// What a setup reads of this machine: the reviewer CLIs, the Decisions key,
/// how the repository already works, and the `PATH` checks run with.
pub fn machine(root: &Path) -> Machine {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let clis = Agent::ALL
        .iter()
        .map(|agent| {
            let program = devflow_engine::agents::Cli::of(agent.word())
                .map_or(agent.word(), devflow_engine::agents::Cli::program);
            Cli {
                name: *agent,
                installed: devflow_engine::env::found_on(&path, program.as_ref()).is_some(),
                signed_in: None,
            }
        })
        .collect();
    Machine {
        clis,
        decisions_key: super::jev::key().is_some(),
        decisions_opted_out: false,
        branches: devflow_engine::git::branches(root).unwrap_or_default(),
        subjects: devflow_engine::git::subjects(root, 200),
        installed_skills: installed_skills(),
        path: Some(path),
    }
}

/// The skills already installed for Claude Code, by name.
fn installed_skills() -> Vec<String> {
    let Some(folder) = project::installed_skills_folder() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(folder) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| entry.path().join("SKILL.md").is_file())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .take(200)
        .collect()
}
