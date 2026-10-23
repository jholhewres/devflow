//! `brief` and `plan`: the brief as an epic work item, and the plan as its
//! items, each with its criteria and the items it waits on.
//!
//! A plan is a preview before any item exists. It waits beside the epic,
//! where the person can read or edit it; an agent creates the items with
//! `apply` only after the person's yes, and then only the plan they last saw.

use std::time::SystemTime;

use devflow_engine::brief::{self, Brief};
use devflow_engine::config::Config;
use devflow_engine::jev::{self as rules, Said};
use devflow_engine::plan::{self, Slice, PREFIX};
use devflow_engine::work::{Closed, Kind, New, WorkItems};
use devflow_engine::State;
use serde_json::{json, Value};

use super::jev::{self, Jev};
use super::{item_here, text};
use crate::project::Project;
use crate::server::Server;

/// The config and Jev, where the flow is on and Decisions is used.
fn judging(
    server: &Server,
    project: &Project,
    epic: Option<&str>,
) -> (Option<Config>, Option<Jev>) {
    let config = match project.read() {
        State::Valid(_, config) => Some(*config),
        _ => None,
    };
    let jev = config
        .as_ref()
        .and_then(|config| Jev::of(server, project, config, epic, &[]));
    (config, jev)
}

pub fn brief(server: &Server, params: Value) -> Result<Value, String> {
    let project = server.project();
    let state = project.read();
    let config = super::config_for(&project, &state, &server.consent, "briefing")
        .or_else(|_| super::config_for(&project, &state, &server.consent, "context"))?;
    let context_on = config.stages.on("context");
    let given: Brief = serde_json::from_value(strip(&params, &["item", "card"])).map_err(|why| {
        format!("a brief is {{ title, goal, for_whom, success, out_of_scope, constraints, decisions, context, item }}: {why}")
    })?;
    if !given.has_fields() && given.context.is_none() && given.title.is_none() {
        return Err("nothing to write: pass the brief's fields, or `context`".to_owned());
    }
    let item = super::item_of(&params)
        .map(|id| item_here(&project, &id))
        .transpose()?;
    let title = match (&given.title, &item) {
        (Some(title), _) if !title.trim().is_empty() => brief::epic_title(title),
        (_, Some(item)) => item.title.clone(),
        _ => {
            return Err(
                "a new epic needs a `title`; pass `item` to write onto one that exists".to_owned(),
            )
        }
    };
    let body = brief::written(item.as_ref().map_or("", |item| &item.body), &given);
    if body.len() > brief::LONGEST {
        return Err(format!(
            "the brief is past {} bytes; say it shorter",
            brief::LONGEST
        ));
    }
    let items = project.items();
    let (id, created) = match item {
        Some(item) => {
            items.update_body(&item.id, &body)?;
            if title != item.title {
                items.retitle(&item.id, &title)?;
            }
            (item.id, false)
        }
        None => {
            let made = items.create(
                &New {
                    title: title.clone(),
                    kind: Kind::Epic,
                    parent: None,
                    depends_on: Vec::new(),
                    body,
                },
                SystemTime::now(),
            )?;
            (made.id, true)
        }
    };
    Ok(json!({
        "item": id,
        "title": title,
        "created": created,
        "file": format!("{}/{id}.md", items.relative()),
        "note": after_brief(given.context.is_some(), context_on),
    }))
}

/// `params` without the fields the engine's type does not take.
fn strip(params: &Value, fields: &[&str]) -> Value {
    let mut params = params.clone();
    if let Some(object) = params.as_object_mut() {
        for field in fields {
            object.remove(*field);
        }
    }
    params
}

/// The stage a brief's note sends the agent to next.
pub fn after_brief(context_written: bool, context_on: bool) -> &'static str {
    match (context_written, context_on) {
        (true, _) => {
            "Written. The next stage is the plan (devflow-plan), when the person asks for it."
        }
        (false, true) => {
            "Written. The next stage is the context (devflow-context), when the person asks for it."
        }
        (false, false) => {
            "Written. The context stage is off in devflow.yaml, so the next stage is the plan \
             (devflow-plan), when the person asks for it."
        }
    }
}

pub fn plan(server: &Server, params: Value) -> Result<Value, String> {
    let project = server.project();
    let epic = text(&params, "epic");
    if ["merge", "cut"]
        .iter()
        .any(|key| params.get(*key).is_some_and(|given| !given.is_null()))
    {
        let state = project.read();
        super::config_for(&project, &state, &server.consent, "plan")?;
        return edited(&project, &params);
    }
    let Some(epic) = epic else {
        return previewed(&params);
    };
    let state = project.read();
    let config = super::config_for(&project, &state, &server.consent, "plan")?;
    plan::published(config)?;
    let (config, jev) = judging(server, &project, Some(&epic));
    let mut answer = planned(&project, &epic, &params, config.as_ref().zip(jev.as_ref()))?;
    if let Some(config) = &config {
        answer["decisions"] = jev::decisions_of(config, jev.as_ref());
    }
    Ok(answer)
}

/// A plan with no epic: its items read and checked, made nowhere, kept nowhere.
pub fn previewed(params: &Value) -> Result<Value, String> {
    if params.get("apply").and_then(Value::as_bool) == Some(true) {
        return Err("a plan's items are made under their epic: pass `epic`".to_owned());
    }
    let slices = plan::read(
        params
            .get("items")
            .or(params.get("cards"))
            .unwrap_or(&Value::Null),
    )?;
    Ok(json!({
        "applied": false,
        "epic": Value::Null,
        "preview": preview_of(&slices),
        "note": "Nothing was made, and nothing is kept: with no epic, this plan is the preview \
                 alone. To make its items, brief the work as an epic (devflow-briefing) and plan \
                 it with `epic`.",
    }))
}

fn preview_of(slices: &[Slice]) -> Vec<Value> {
    slices
        .iter()
        .map(|slice| {
            json!({
                "key": slice.key,
                "title": plan::title(slice),
                "blocked_by": slice.depends_on,
            })
        })
        .collect()
}

/// Jev's word on a stage's work, by the rubric devflow.yaml gives it.
fn judge(
    judged: Option<(&Config, &Jev)>,
    stage: &str,
    state: impl FnOnce() -> Value,
) -> Option<Said> {
    let (config, jev) = judged?;
    let rubric = rules::rubric_for(config, stage)?;
    Some(jev.judge(&rubric, &state()))
}

fn jev_said(brief: Option<&Said>, plan: Option<&Said>) -> Value {
    json!({ "brief": brief.map(Said::to_json), "plan": plan.map(Said::to_json) })
}

/// Each slice's waits outside its plan, by item id: refused when one names
/// no item of this project.
fn outside_items(project: &Project, slices: &[Slice]) -> Result<Vec<Vec<String>>, String> {
    slices
        .iter()
        .enumerate()
        .map(|(at, slice)| {
            plan::outside(slices, slice)
                .into_iter()
                .map(|on| {
                    let id = on.trim_start_matches('#');
                    item_here(project, id).map(|item| item.id).map_err(|_| {
                        format!(
                            "item {} ({}): depends_on `{on}` is no work item of this project",
                            at + 1,
                            slice.key
                        )
                    })
                })
                .collect()
        })
        .collect()
}

fn slices_of(kept: &Value) -> Vec<Slice> {
    serde_json::from_value(kept["cards"].clone()).unwrap_or_default()
}

fn planned(
    project: &Project,
    epic: &str,
    params: &Value,
    judged: Option<(&Config, &Jev)>,
) -> Result<Value, String> {
    let epic_item = item_here(project, epic)?;
    let items = project.items();
    let apply = params.get("apply").and_then(Value::as_bool) == Some(true);
    let kept = items.plan(epic)?;
    let given = params.get("items").or(params.get("cards"));
    let slices = match given {
        // An apply that names no items is the yes to the preview the person saw.
        None | Some(Value::Null) if apply => kept
            .as_ref()
            .map(slices_of)
            .ok_or("there is no preview on this epic to apply: send the items first")?,
        given => plan::read(given.unwrap_or(&Value::Null))?,
    };
    outside_items(project, &slices)?;
    let brief = judge(judged, "briefing", || {
        rules::brief_state(
            &epic_item.title,
            &brief::read(&epic_item.body).unwrap_or_default(),
        )
    });
    if let Some(held) = brief.as_ref().and_then(rules::holds) {
        return Err(format!(
            "{held}: write the brief's goal, out of scope and success with `brief` \
             (devflow-briefing), then plan again"
        ));
    }
    if let (true, Some(row)) = (apply, &kept) {
        if !row["created"].is_null() {
            return Ok(said_created(epic, &row["created"], false));
        }
        let shown = slices_of(row);
        if row["edited"] == true || shown == slices {
            let plan = judge(judged, "plan", || rules::plan_state(&shown));
            if let Some(held) = plan.as_ref().and_then(rules::holds) {
                return Err(format!(
                    "{held}: nothing was made. Make each item a vertical slice with testable \
                     criteria and the items it waits on, then show the plan again"
                ));
            }
            let made = create(project, epic, &shown)?;
            let mut said = said_created(epic, &made, true);
            if judged.is_some() {
                said["jev"] = jev_said(brief.as_ref(), plan.as_ref());
            }
            return Ok(said);
        }
    }
    items.keep_plan(
        epic,
        &json!({ "cards": slices, "edited": false, "created": null }),
    )?;
    let plan = judge(judged, "plan", || rules::plan_state(&slices));
    let warning = plan.as_ref().and_then(rules::holds).map(|held| {
        format!("{held}: applied as it is, nothing would be made; fix the items first")
    });
    let note = if apply {
        "Nothing was made: the person has not seen these items, so they are now the preview. \
         Show them, and apply once the person says yes to them."
    } else {
        "Nothing was made. The plan waits beside the epic. After the person's explicit yes, \
         call again with the same items and apply: true."
    };
    let mut said = json!({
        "applied": false,
        "epic": epic,
        "preview": preview_of(&slices),
        "kept": format!("{}/{epic}.plan.json", items.relative()),
        "note": note,
    });
    if judged.is_some() {
        said["jev"] = jev_said(brief.as_ref(), plan.as_ref());
    }
    if let Some(warning) = warning {
        said["warning"] = json!(warning);
    }
    Ok(said)
}

/// The epic's plan made into its items, and kept as made.
fn create(project: &Project, epic: &str, slices: &[Slice]) -> Result<Value, String> {
    let items = project.items();
    let waits = plan::waits_on(slices);
    let outside = outside_items(project, slices)?;
    let mut ids: Vec<String> = Vec::with_capacity(slices.len());
    let now = SystemTime::now();
    for (at, slice) in slices.iter().enumerate() {
        let depends_on: Vec<String> = waits[at]
            .iter()
            .map(|before| ids[*before].clone())
            .chain(outside[at].iter().cloned())
            .collect();
        let made = items.create(
            &New {
                title: plan::title(slice),
                kind: Kind::Item,
                parent: Some(epic.to_owned()),
                depends_on,
                body: plan::body(slice),
            },
            now,
        )?;
        ids.push(made.id);
    }
    let created = json!({
        "by": "agent",
        "cards": slices.iter().zip(&ids).map(|(slice, id)| json!({
            "key": slice.key,
            "item": id,
            "title": plan::title(slice),
            "blocked_by": slice.depends_on,
        })).collect::<Vec<_>>(),
    });
    items.keep_plan(
        epic,
        &json!({ "cards": slices, "edited": false, "created": created }),
    )?;
    let _ = items.comment(
        epic,
        "agent",
        &format!(
            "{PREFIX}Plan made after the person's yes in the conversation: {} items.",
            slices.len()
        ),
        now,
    );
    Ok(created)
}

/// The answer once the items exist: made by this call, or earlier.
fn said_created(epic: &str, created: &Value, now: bool) -> Value {
    let made = created.get("cards").cloned().unwrap_or_else(|| json!([]));
    let starts: Vec<Value> = made
        .as_array()
        .into_iter()
        .flatten()
        .filter(|item| item["blocked_by"].as_array().is_none_or(Vec::is_empty))
        .map(|item| item["item"].clone())
        .collect();
    json!({
        "applied": true,
        "epic": epic,
        "items": made,
        "starts_now": starts,
        "note": if now {
            "Made under the epic. The items in starts_now wait on nothing and can start now."
        } else {
            "This plan was already applied: these are its items."
        },
    })
}

/// `merge: { from, into }` or `cut`: a preview, or with `apply` after the
/// person's yes, the change.
fn edited(project: &Project, params: &Value) -> Result<Value, String> {
    let (item, closed, said) = match (params.get("merge"), text(params, "cut")) {
        (Some(merge), _) if !merge.is_null() => {
            let from = text(merge, "from").ok_or("merge takes { from, into }")?;
            let into = text(merge, "into").ok_or("merge takes { from, into }")?;
            let (from, into) = (item_here(project, &from)?, item_here(project, &into)?);
            let said = format!(
                "\"{}\" ({}) merged into \"{}\" ({}): it finishes on that item's evidence",
                from.title, from.id, into.title, into.id
            );
            (from, Closed::Into(into.id), said)
        }
        (_, Some(cut)) => {
            let item = item_here(project, &cut)?;
            let said = format!(
                "\"{}\" ({}) cut from the plan: it closes without evidence",
                item.title, item.id
            );
            (item, Closed::Cut, said)
        }
        _ => return Err("pass `merge: { from, into }` or `cut`".to_owned()),
    };
    let items = project.items();
    let releases: Vec<Value> = items
        .list()?
        .iter()
        .filter(|one| one.depends_on.contains(&item.id))
        .map(|one| json!({ "id": one.id, "title": one.title }))
        .collect();
    if params.get("apply").and_then(Value::as_bool) != Some(true) {
        return Ok(json!({
            "applied": false,
            "change": said,
            "releases": releases,
            "note": "Nothing was changed. Show the person this change and the items it lets \
                     start; after their explicit yes, call again with the same change and \
                     apply: true.",
        }));
    }
    items.close(&item.id, closed)?;
    let _ = items.comment(
        &item.id,
        "agent",
        &format!("{PREFIX}{said}, after the person's yes in the conversation."),
        SystemTime::now(),
    );
    Ok(json!({
        "applied": true,
        "change": said,
        "releases": releases,
        "note": "Changed. The items in releases no longer wait on it.",
    }))
}
