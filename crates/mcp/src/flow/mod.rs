//! The flow's tools, each answered in this process from the project's files:
//! its devflow.yaml, its work items, its runs, and the person's decisions
//! kept on this machine.

use std::path::Path;

use devflow_engine::config::Config;
use devflow_engine::runner::Context;
use devflow_engine::work::{WorkItem, WorkItems};
use devflow_engine::{Ask, State};
use serde_json::Value;

use crate::consent::Consent;
use crate::project::Project;

pub mod brief;
pub mod evidence;
pub mod gate;
pub mod items;
pub mod jev;
pub mod next;
pub mod publish;
pub mod review;
pub mod setup;
pub mod skill;
pub mod stage;

/// Who signs what devflow writes on a work item.
pub const SIGNED: &str = "devflow";

/// What the flow offers a project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Offered {
    /// The setup tools.
    Setup,
    /// Those, and the tools of the stages switched on.
    Active(Vec<&'static str>),
}

/// The offer, from the file and the person's switch on this machine.
pub fn offered(state: &State, switched_on: bool) -> Offered {
    match state {
        State::Valid(_, config) if config.enabled && switched_on => {
            Offered::Active(config.stages_on())
        }
        _ => Offered::Setup,
    }
}

/// The stages switched on, when devflow is on here.
pub fn stages_on(
    project: &Project,
    state: &State,
    consent: &Consent,
) -> Result<Vec<&'static str>, String> {
    match offered(state, consent.made(&project.root, Ask::Enable)) {
        Offered::Active(stages) => Ok(stages),
        Offered::Setup => Err("devflow is not on in this project: `status` says why.".to_owned()),
    }
}

/// The configuration, when devflow is on here with `stage` switched on.
pub fn config_for<'a>(
    project: &Project,
    state: &'a State,
    consent: &Consent,
    stage: &str,
) -> Result<&'a Config, String> {
    let stages = stages_on(project, state, consent)?;
    match state {
        State::Valid(_, config) if stages.contains(&stage) => Ok(config),
        State::Valid(..) => Err(format!(
            "devflow's {stage} stage is switched off in this project's devflow.yaml."
        )),
        _ => Err("devflow.yaml does not read: `status` says why.".to_owned()),
    }
}

/// A text field, trimmed, when it says something.
pub fn text(params: &Value, name: &str) -> Option<String> {
    params
        .get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// The work item a call names, as `item` (or `card`, devpit's word).
pub fn item_of(params: &Value) -> Option<String> {
    text(params, "item").or_else(|| text(params, "card"))
}

/// The params as the engine reads them: `item` is its `card`.
pub fn as_engine(params: &Value) -> Value {
    let mut params = params.clone();
    if let Some(fields) = params.as_object_mut() {
        if let Some(item) = fields.remove("item") {
            fields.entry("card").or_insert(item);
        }
    }
    params
}

/// A work item of this project, by id.
pub fn item_here(project: &Project, id: &str) -> Result<WorkItem, String> {
    project.items().get(id)?.ok_or_else(|| {
        format!(
            "there is no work item `{id}` in {}",
            project.items().relative()
        )
    })
}

/// What a check, a stage's gate or a reviewer is told of the item, through
/// its environment only.
pub fn context_of(project: &Project, item: &WorkItem) -> Context {
    let root = project.root.display().to_string();
    Context {
        project: project.name(),
        project_path: root.clone(),
        worktree_path: root,
        branch: devflow_engine::git::branch_at(&project.root).unwrap_or_default(),
        base_ref: devflow_engine::started::start_of(&project.runs(), &item.id).unwrap_or_default(),
        item: item.id.clone(),
        item_title: item.title.clone(),
        ..Context::default()
    }
}

/// The secrets devflow knows of, taken out of a text before it is kept:
/// the Decisions key.
pub fn redact(text: &str) -> String {
    match jev::key() {
        Some(key) if key.len() >= 8 => text.replace(&key, "[hidden]"),
        _ => text.to_owned(),
    }
}

/// A JSON file of a run, read with a ceiling.
pub fn json_at(path: &Path) -> Option<Value> {
    const MOST_READ: u64 = 4 * 1024 * 1024;
    let file = std::fs::File::open(path).ok()?;
    let raw = devflow_engine::fsguard::read_within(file, MOST_READ).ok()??;
    serde_json::from_slice(&raw).ok()
}

/// A comment devflow leaves on a work item; failing to write one never fails
/// the call that made it.
pub fn signed(project: &Project, item: &str, text: &str) {
    let _ = project
        .items()
        .comment(item, SIGNED, text, std::time::SystemTime::now());
}

/// What a run's files are called, relative to the project's root.
pub fn links(project: &Project, run: &Path, files: &[String]) -> Vec<(String, String)> {
    files
        .iter()
        .map(|file| {
            let at = run.join(file);
            let shown = at
                .strip_prefix(&project.root)
                .map(|relative| relative.display().to_string())
                .unwrap_or_else(|_| at.display().to_string());
            (file.clone(), shown)
        })
        .collect()
}
