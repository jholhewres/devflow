//! `next`: an epic's next work item by its blockers, the pure half of
//! devpit's autopilot. Starting a session on it is the agent's, or the person's.

use devflow_engine::autopilot::{self, Next, Planned, Standing};
use devflow_engine::config::{Approve, Config};
use devflow_engine::work::{State, WorkItem, WorkItems};
use serde_json::{json, Value};

use super::gate::newest;
use super::text;
use crate::project::Project;
use crate::server::Server;

/// A flow that asks the person to approve every item once it finished.
pub fn approve_each(config: &Config) -> bool {
    config
        .flow
        .iter()
        .skip_while(|step| step.builtin() != Some("plan"))
        .skip(1)
        .filter(|step| config.is_on(step))
        .any(|step| step.own.as_ref().and_then(|own| own.approve) == Some(Approve::Person))
}

/// Where an item stands: done, finished (its gate passed, waiting to be
/// checked), at work, or waiting.
fn standing(project: &Project, item: &WorkItem) -> Standing {
    match item.state {
        State::Done => Standing::Done,
        State::Doing
            if newest(&project.runs(), &item.id, "gate.json")
                .is_some_and(|(_, gate)| gate["passed"] == true) =>
        {
            Standing::Finished
        }
        State::Doing => Standing::Working,
        State::Open => Standing::Waiting,
    }
}

pub fn next(server: &Server, params: Value) -> Result<Value, String> {
    let project = server.project();
    let state = project.read();
    let config = super::config_for(&project, &state, &server.consent, "plan")?;
    let epic = text(&params, "epic").ok_or("which epic? pass its id as `epic`")?;
    super::item_here(&project, &epic)?;
    let all = project.items().list()?;
    let done = |id: &str| {
        all.iter()
            .find(|item| item.id == id)
            .is_some_and(|item| item.state == State::Done)
    };
    let planned: Vec<Planned> = all
        .iter()
        .filter(|item| item.parent.as_deref() == Some(epic.as_str()))
        .map(|item| Planned {
            id: item.id.clone(),
            title: item.title.clone(),
            blocked_by: item
                .depends_on
                .iter()
                .map(|by| (by.clone(), done(by)))
                .collect(),
            standing: standing(&project, item),
        })
        .collect();
    if planned.is_empty() {
        return Err(format!(
            "epic {epic} has no items yet: `plan` makes them, after the person's yes"
        ));
    }
    let order: Vec<Value> = autopilot::ordered(&planned)
        .map(|order| {
            order
                .iter()
                .map(|item| json!({ "id": item.id, "title": item.title }))
                .collect()
        })
        .unwrap_or_default();
    let said = match autopilot::next(&planned, approve_each(config)) {
        Next::Start(id) => json!({
            "next": "start", "item": id,
            "note": "Call `start` with this item, then follow the flow through `gate`.",
        }),
        Next::Working(id) => json!({
            "next": "working", "item": id,
            "note": "This item is at work: one at a time, the next builds on what it leaves.",
        }),
        Next::Approve { card, why } => json!({ "next": "approve", "item": card, "note": why }),
        Next::Blocked { card, why } => json!({ "next": "blocked", "item": card, "note": why }),
        Next::Done => json!({ "next": "done", "note": "Every item of the epic is done." }),
    };
    let mut said = said;
    said["epic"] = json!(epic);
    said["order"] = json!(order);
    Ok(said)
}
