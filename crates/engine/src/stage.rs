//! An own stage's gate, as a card passes it: a command that exits 0, or a
//! rubric Decisions answers. Each pass is kept as `stage-<name>.json` in a
//! run of the card, and the completion gate reads the newest one.
//!
//! A command a team layer brought is somebody else's code: it runs only
//! once the person confirmed that exact command at that exact commit.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::config::{Config, StageGate, Step};

/// The record of a stage's gate, in a run of the card.
pub fn file_of(stage: &str) -> String {
    format!("stage-{stage}.json")
}

/// The own stage called `name`, switched on, with a gate.
pub fn gated<'a>(config: &'a Config, name: &str) -> Result<(&'a Step, &'a StageGate), String> {
    let step = config
        .flow
        .iter()
        .find(|step| step.name() == name && step.builtin().is_none())
        .ok_or_else(|| {
            let own: Vec<&str> = config
                .flow
                .iter()
                .filter(|step| step.builtin().is_none())
                .map(Step::name)
                .collect();
            format!(
                "`{name}` is not one of this project's own stages: {}",
                if own.is_empty() {
                    "it has none".to_owned()
                } else {
                    own.join(", ")
                }
            )
        })?;
    if !config.is_on(step) {
        return Err(format!(
            "the stage `{name}` is switched off in devflow.yaml"
        ));
    }
    let gate = step
        .own
        .as_ref()
        .and_then(|own| own.gate.as_ref())
        .ok_or_else(|| {
            format!("the stage `{name}` has no gate: following its skill is the stage")
        })?;
    Ok((step, gate))
}

/// What a confirmation of a layer's command is kept as: the command, where
/// it came from and the commit it came at. Any of them changing asks again.
pub fn fingerprint(git: &str, commit: &str, command: &str) -> String {
    let digest = Sha256::digest(format!("{git}\n{commit}\n{command}").as_bytes());
    format!("sha256:{digest:x}")
}

/// `stage-<name>.json`: how the gate ended, and when.
pub fn recorded(stage: &str, gate: &StageGate, passed: bool, at: &str, said: &[String]) -> Value {
    let (kind, what) = match gate {
        StageGate::Command(command) => ("command", command),
        StageGate::Rubric(rubric) => ("rubric", rubric),
    };
    json!({ "stage": stage, "gate": kind, "what": what, "passed": passed, "at": at, "said": said })
}

#[cfg(test)]
#[path = "stage_tests.rs"]
mod tests;
