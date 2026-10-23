//! `stage`: one of the project's or a team's own stages. Without an item it
//! is the stage's skill, read where it is; with an item it runs the stage's
//! gate and keeps how it ended as `stage-<name>.json` in a run of the item,
//! which the completion gate reads.
//!
//! A command runs as a check does, the item reaching it only through the
//! environment. A command a team layer brought runs only once the person
//! confirmed it in a terminal (`devflow stage confirm <name>`).

use std::time::{Duration, SystemTime};

use devflow_engine::config::{Config, Mode, StageGate, Step};
use devflow_engine::layers::Layered;
use devflow_engine::work::WorkItem;
use devflow_engine::{runs, skills, stage};
use serde_json::{json, Value};

use super::jev::{self, Jev};
use super::{context_of, item_here, item_of, signed};
use crate::consent::Consent;
use crate::project::{self, Project};
use crate::server::Server;

/// The longest a stage's command runs: it is a gate, not a test suite.
const LONGEST: Duration = Duration::from_secs(10 * 60);
/// The output kept of a gate that failed, from its end.
const TAIL: usize = 20;

pub fn stage(server: &Server, params: Value) -> Result<Value, String> {
    let project = server.project();
    let state = project.read();
    super::stages_on(&project, &state, &server.consent)?;
    let devflow_engine::State::Valid(_, config) = &state else {
        return Err("devflow.yaml does not read: `status` says why".to_owned());
    };
    let name = params
        .get("stage")
        .and_then(Value::as_str)
        .ok_or("pass the own stage's name as `stage`")?;
    let layered = project.layered();
    let Some(id) = item_of(&params) else {
        return skill_of(&project, config, layered.as_ref(), name);
    };
    let (step, gate) = stage::gated(config, name)?;
    let item = item_here(&project, &id)?;
    let (passed, said, decisions) = match gate {
        StageGate::Command(command) => {
            confirmed(&server.consent, layered.as_ref(), step, command)?;
            let (passed, said) = ran(command, &project, &item, name);
            (passed, said, None)
        }
        StageGate::Rubric(rubric) => {
            let jev = Jev::of(server, &project, config, Some(&item.id), &[]);
            let (passed, said) = judged(jev.as_ref(), &item, name, rubric);
            (passed, said, Some(jev::decisions_of(config, jev.as_ref())))
        }
    };
    let at = SystemTime::now();
    let path = project.runs().fresh(&item.id, at)?;
    let file = stage::file_of(name);
    let record = stage::recorded(name, gate, passed, &runs::stamp(at), &said);
    std::fs::write(
        path.join(&file),
        serde_json::to_string_pretty(&record).unwrap_or_default(),
    )
    .map_err(|err| format!("{}/{file}: {err}", path.display()))?;
    let headline = format!(
        "{}stage {name}: {}",
        devflow_engine::plan::PREFIX,
        if passed { "passed" } else { "failed" }
    );
    let comment = match said.first() {
        Some(first) => format!("{headline}\n\n{first}"),
        None => headline,
    };
    signed(&project, &item.id, &comment);
    let mut answer = json!({
        "stage": name,
        "uses": step.uses,
        "result": if passed { "passed" } else { "failed" },
        "said": said,
        "record": format!("{}/{file}", path.display()),
        "next": if passed {
            "Go on to the next stage; `gate` reads this record at the end."
        } else {
            "Fix what the gate says, then call `stage` again."
        },
    });
    if let Some(decisions) = decisions {
        answer["decisions"] = decisions;
    }
    Ok(answer)
}

/// An own stage's skill, from wherever `uses` points; never copied.
fn skill_of(
    project: &Project,
    config: &Config,
    layered: Option<&Layered>,
    name: &str,
) -> Result<Value, String> {
    let step = config
        .flow
        .iter()
        .find(|step| step.name() == name && step.builtin().is_none() && config.is_on(step))
        .ok_or_else(|| format!("`{name}` is not an own stage switched on in this project"))?;
    let personal = project::personal_skills();
    let installed = project::installed_skills_folder();
    let teams = layered
        .map(|one| one.applied.as_slice())
        .unwrap_or_default();
    let found = skills::own(
        &step.uses,
        &skills::Places {
            project: &project.root,
            personal: &personal,
            teams,
            installed: installed.as_deref(),
        },
    )?;
    let gate = step.own.as_ref().and_then(|own| own.gate.as_ref());
    Ok(json!({
        "stage": name,
        "uses": step.uses,
        "layer": found.layer,
        "file": found.file.map(|file| file.display().to_string()),
        "text": found.text,
        "approve": step.own.as_ref().and_then(|own| own.approve).map(|approve| approve.word()),
        "gate": match gate {
            Some(StageGate::Command(command)) => json!({ "command": command }),
            Some(StageGate::Rubric(rubric)) => json!({ "rubric": rubric }),
            None => Value::Null,
        },
        "next": if gate.is_some() {
            "Follow the skill, then call `stage` with this stage and the item to pass its gate."
        } else {
            "Follow the skill: the stage has no gate."
        },
    }))
}

/// The team layer that brought a stage's command, its commit and the
/// command's fingerprint; `None` when the command is the project's own or
/// the person's.
pub fn team_command(layered: Option<&Layered>, command: &str) -> Option<(String, String, String)> {
    let layered = layered?;
    let team = layered
        .applied
        .iter()
        .find(|team| team.name == layered.stages_from)?;
    Some((
        team.name.clone(),
        team.commit.clone(),
        stage::fingerprint(&team.git, &team.commit, command),
    ))
}

/// A team layer's command runs once the person confirmed it at this commit.
fn confirmed(
    consent: &Consent,
    layered: Option<&Layered>,
    step: &Step,
    command: &str,
) -> Result<(), String> {
    let Some((team, commit, print)) = team_command(layered, command) else {
        return Ok(());
    };
    if consent.command_confirmed(&print) {
        return Ok(());
    }
    let short = commit.get(..12).unwrap_or(&commit);
    Err(format!(
        "the stage `{}` runs a command from the {team} layer at {short} that the person has not \
         confirmed: `{command}`. The person runs `devflow stage confirm {}` in a terminal; call \
         again once they did.",
        step.name(),
        step.name(),
    ))
}

/// The command, run as a check runs: the item in its environment only.
fn ran(command: &str, project: &Project, item: &WorkItem, name: &str) -> (bool, Vec<String>) {
    let mut context = context_of(project, item);
    context
        .shared
        .push(("DEVFLOW_STAGE".to_owned(), name.to_owned()));
    let mut output: Vec<String> = Vec::new();
    let ended = devflow_engine::runner::run(
        command,
        &project.root,
        &context,
        Some(LONGEST),
        |_| {},
        |said| {
            output.push(said.text.chars().take(300).collect());
            if output.len() > 4 * TAIL {
                output.drain(..TAIL);
            }
        },
    );
    match ended {
        Ok(ended) if ended.exit_code == Some(0) && !ended.timed_out => (true, Vec::new()),
        Ok(ended) => {
            let mut said = vec![if ended.timed_out {
                format!(
                    "`{command}` was stopped after {} min",
                    LONGEST.as_secs() / 60
                )
            } else {
                format!("`{command}` exited {}", ended.exit_code.unwrap_or(-1))
            }];
            let tail = output.len().saturating_sub(TAIL);
            said.extend(output.drain(tail..));
            (false, said)
        }
        Err(err) => (false, vec![format!("`{command}` did not run: {err}")]),
    }
}

/// A rubric gate: Decisions answers where the project uses it, and holds the
/// item only in `enforce`; without it the stage passes, as the gate does.
fn judged(jev: Option<&Jev>, item: &WorkItem, name: &str, rubric: &str) -> (bool, Vec<String>) {
    let Some(jev) = jev else {
        return (
            true,
            vec![format!(
                "{rubric} not asked: this project does not use Decisions"
            )],
        );
    };
    let state = devflow_engine::jev::capped(&json!({
        "card": { "id": item.id, "title": item.title, "body": item.body },
        "stage": name,
    }));
    let said = jev.judge(rubric, &state);
    let holds = said.mode == Mode::Enforce && said.outcome == "fail";
    let mut lines = vec![format!("{rubric}: {} ({})", said.outcome, said.mode.word())];
    lines.extend(said.skipped.clone());
    if said.skipped.is_none() {
        lines.extend(said.failing());
    }
    (!holds, lines)
}
