//! Version 2's list of stages: each `uses:` a skill, devpit's own under
//! `builtin/` or the project's, the person's or a team's own, in the order
//! the work reaches them; and the `extends` and `locked` beside it.

use serde_json::{json, Value as Json};

use crate::config::{
    approved_in, boolean, execution_in, is_name, items, joined, name, text, word, Approve, Config,
    Extend, Fields, Invalid, Own, StageGate, Stages, Step, BUILTIN, GATE, STAGES,
};
use crate::node::{Node, Value};

/// Where an own stage's skill is read from, besides a team's name.
pub const PLACES: [&str; 3] = ["project", "personal", "skills"];

/// The list's stages, and the built-in settings they carry. A built-in stage
/// left out of the list is off.
pub(crate) fn read(node: &Node, path: &str) -> Result<(Stages, Vec<Step>), Invalid> {
    let mut stages = Config::default().stages;
    for stage in STAGES {
        stages.switch(stage, false);
    }
    let mut flow: Vec<Step> = Vec::new();
    for (index, item) in items(node, path)?.iter().enumerate() {
        // Named by its stage, as a change to it is: `stages.plan.approve`.
        let at = match named(item) {
            Some(name) if !flow.iter().any(|one| one.name() == name) => format!("{path}.{name}"),
            _ => format!("{path}.{index}"),
        };
        let step = step(item, &at, &mut stages)?;
        if flow.iter().any(|one| one.name() == step.name()) {
            return Err(Invalid::at(
                item.line(),
                &joined(&at, "uses"),
                &format!("a stage called `{}` is already listed", step.name()),
            ));
        }
        flow.push(step);
    }
    Ok((stages, flow))
}

/// The name an item's `uses:` gives it, before it is read.
fn named(item: &Node) -> Option<&str> {
    let Value::Map(fields) = &item.value else {
        return None;
    };
    let (_, uses) = fields.iter().find(|(key, _)| key.name == "uses")?;
    match &uses.value {
        Value::Scalar(uses, _) => uses.rsplit('/').next().filter(|name| is_name(name)),
        _ => None,
    }
}

/// `uses:` as devpit reads it: `builtin/<stage>`, or `<where>/<name>`.
fn uses(node: &Node, path: &str) -> Result<String, Invalid> {
    let given = text(node, path, 120)?;
    let well = match given.split_once('/') {
        Some((BUILTIN, stage)) => STAGES.contains(&stage),
        Some((place, skill)) => is_name(place) && is_name(skill),
        None => false,
    };
    if !well {
        return Err(Invalid::at(
            node.line(),
            path,
            &format!(
                "`{given}` is not a stage: builtin/<one of {}>, or <where>/<skill> where is {}, or a team's name",
                STAGES.join(", "),
                PLACES.join(", ")
            ),
        ));
    }
    Ok(given)
}

fn step(node: &Node, path: &str, stages: &mut Stages) -> Result<Step, Invalid> {
    let mut fields = Fields::of(node, path)?;
    let line = fields.line;
    let uses = match fields.get("uses") {
        Some((node, path)) => uses(node, &path)?,
        None => {
            return Err(Invalid::at(
                line,
                &joined(path, "uses"),
                "a stage needs `uses:`, the skill it follows",
            ))
        }
    };
    let step = Step { uses, own: None };
    let Some(builtin) = step.builtin() else {
        let enabled = boolean(fields.get("enabled"), true)?;
        let approve = match fields.get("approve") {
            Some((node, path)) => {
                Some(word(node, &path, Approve::of, Approve::ALL, Approve::word)?)
            }
            None => None,
        };
        let gate = match fields.get("gate") {
            Some((node, path)) => Some(gate(node, &path)?),
            None => None,
        };
        fields.done()?;
        return Ok(Step {
            own: Some(Own {
                enabled,
                approve,
                gate,
            }),
            ..step
        });
    };
    match builtin {
        "briefing" => stages.briefing = approved_in(&mut fields, false)?,
        "plan" => stages.plan = approved_in(&mut fields, true)?,
        "execution" => stages.execution = execution_in(&mut fields)?,
        "completion" => {
            stages.completion.enabled = boolean(fields.get("enabled"), true)?;
            stages.completion.gate = match fields.get("gate") {
                Some((node, path)) => match gate(node, &path)? {
                    StageGate::Rubric(rubric) => rubric,
                    StageGate::Command(_) => {
                        return Err(Invalid::at(
                            node.line(),
                            &path,
                            "the completion stage is gated by a rubric; a command is a check of the execution stage",
                        ))
                    }
                },
                None => GATE.to_owned(),
            };
        }
        stage => {
            let on = boolean(fields.get("enabled"), true)?;
            stages.switch(stage, on);
        }
    }
    fields.done()?;
    Ok(step)
}

/// A gate: a rubric's name, or `{ command: … }` / `{ rubric: … }`.
fn gate(node: &Node, path: &str) -> Result<StageGate, Invalid> {
    if let Value::Scalar(..) = node.value {
        return Ok(StageGate::Rubric(name(node, path)?));
    }
    let mut fields = Fields::of(node, path)?;
    let command = fields.get("command");
    let rubric = fields.get("rubric");
    let gate = match (command, rubric) {
        (Some((node, path)), None) => StageGate::Command(text(node, &path, 1000)?),
        (None, Some((node, path))) => StageGate::Rubric(name(node, &path)?),
        _ => {
            return Err(Invalid::at(
                node.line(),
                path,
                "a gate is one `command:` or one `rubric:`",
            ))
        }
    };
    fields.done()?;
    Ok(gate)
}

/// `extends:`: each a repository at a fixed ref.
pub(crate) fn extends(node: &Node, path: &str) -> Result<Vec<Extend>, Invalid> {
    let mut layers: Vec<Extend> = Vec::new();
    for (index, item) in items(node, path)?.iter().enumerate() {
        let at = format!("{path}.{index}");
        let mut fields = Fields::of(item, &at)?;
        let line = fields.line;
        let field = |found: Option<(&Node, String)>, key: &str| match found {
            Some((node, path)) => {
                let given = text(node, &path, 400)?;
                if given.starts_with('-') {
                    return Err(Invalid::at(node.line(), &path, "it cannot start with -"));
                }
                Ok(given)
            }
            None => Err(Invalid::at(
                line,
                &joined(&at, key),
                &format!("a layer needs `{key}:`"),
            )),
        };
        let git = field(fields.get("git"), "git")?;
        let reference = field(fields.get("ref"), "ref")?;
        fields.done()?;
        if layers.iter().any(|one| one.git == git) {
            return Err(Invalid::at(
                line,
                &joined(&at, "git"),
                "this layer is already extended",
            ));
        }
        layers.push(Extend { git, reference });
    }
    Ok(layers)
}

/// `locked:`: dotted paths a later layer may not change.
pub(crate) fn locked(node: &Node, path: &str) -> Result<Vec<String>, Invalid> {
    let mut paths = Vec::new();
    for (index, item) in items(node, path)?.iter().enumerate() {
        let at = format!("{path}.{index}");
        let given = text(item, &at, 200)?;
        if given.split('.').any(str::is_empty) {
            return Err(Invalid::at(
                item.line(),
                &at,
                "a locked field is a dotted path, such as review.block_on",
            ));
        }
        if !paths.contains(&given) {
            paths.push(given);
        }
    }
    Ok(paths)
}

/// One stage as version 2's JSON form says it.
pub(crate) fn step_json(config: &Config, step: &Step) -> Json {
    let stages = &config.stages;
    let mut item = json!({ "uses": step.uses, "enabled": config.is_on(step) });
    match (step.builtin(), &step.own) {
        (Some("briefing"), _) => item["approve"] = json!(stages.briefing.approve),
        (Some("plan"), _) => {
            item["approve"] = json!(stages.plan.approve);
            if let Some(publish) = stages.plan.publish {
                item["publish"] = json!(publish);
            }
            if let Some(unblock_on) = stages.plan.unblock_on {
                item["unblock_on"] = json!(unblock_on);
            }
        }
        (Some("execution"), _) => {
            item["checks"] = json!(stages.execution.checks);
            item["e2e_dir"] = json!(stages.execution.e2e_dir);
        }
        (Some("completion"), _) => item["gate"] = json!(stages.completion.gate),
        (None, Some(own)) => {
            if let Some(approve) = own.approve {
                item["approve"] = json!(approve);
            }
            match &own.gate {
                Some(StageGate::Command(command)) => item["gate"] = json!({ "command": command }),
                Some(StageGate::Rubric(rubric)) => item["gate"] = json!({ "rubric": rubric }),
                None => {}
            }
        }
        _ => {}
    }
    item
}

#[cfg(test)]
#[path = "flow_tests.rs"]
mod tests;
