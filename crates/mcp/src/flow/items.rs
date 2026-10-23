//! The work items, in place of devpit's cards: read, listed, made,
//! commented, started, finished and handed off.

use std::time::SystemTime;

use devflow_engine::work::{Kind, New, State, WorkItems};
use serde_json::{json, Value};

use super::{item_here, item_of, text};
use crate::server::Server;

pub fn item(server: &Server, params: Value) -> Result<Value, String> {
    let project = server.project();
    let items = project.items();
    if let Some(id) = item_of(&params) {
        let item = item_here(&project, &id)?;
        let edited = match (
            text(&params, "title"),
            params.get("body").and_then(Value::as_str),
        ) {
            (None, None) => None,
            (title, body) => {
                if let Some(title) = title {
                    items.retitle(&id, &title)?;
                }
                if let Some(body) = body {
                    items.update_body(&id, body)?;
                }
                Some(item_here(&project, &id)?)
            }
        };
        let item = edited.unwrap_or(item);
        let mut said = item.to_json();
        said["comments"] = json!(items.comments(&id)?);
        said["blocked_by"] = json!(super::gate::blocked_by(&project, &item));
        said["file"] = json!(format!("{}/{id}.md", items.relative()));
        return Ok(said);
    }
    let title = text(&params, "title").ok_or("pass `item` to read one, or `title` to make one")?;
    let kind = match text(&params, "kind").as_deref() {
        None | Some("item") => Kind::Item,
        Some("epic") => Kind::Epic,
        Some(other) => return Err(format!("`kind` is item or epic, not `{other}`")),
    };
    let depends_on: Vec<String> = params
        .get("depends_on")
        .and_then(Value::as_array)
        .map(|ids| {
            ids.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let made = items.create(
        &New {
            title,
            kind,
            parent: text(&params, "parent"),
            depends_on,
            body: params
                .get("body")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        },
        SystemTime::now(),
    )?;
    let mut said = made.to_json();
    said["file"] = json!(format!("{}/{}.md", items.relative(), made.id));
    Ok(said)
}

pub fn items(server: &Server, params: Value) -> Result<Value, String> {
    let project = server.project();
    let state = text(&params, "state");
    let parent = text(&params, "parent");
    let listed: Vec<Value> = project
        .items()
        .list()?
        .into_iter()
        .filter(|item| {
            state
                .as_deref()
                .is_none_or(|state| item.state.word() == state)
        })
        .filter(|item| {
            parent
                .as_deref()
                .is_none_or(|parent| item.parent.as_deref() == Some(parent))
        })
        .map(|item| {
            json!({
                "id": item.id,
                "title": item.title,
                "kind": item.kind,
                "state": item.state,
                "parent": item.parent,
                "depends_on": item.depends_on,
                "blocked_by": super::gate::blocked_by(&project, &item),
            })
        })
        .collect();
    Ok(json!({
        "items": listed,
        "folder": project.items().relative(),
        "current": super::gate::current(&project),
    }))
}

pub fn comment(server: &Server, params: Value) -> Result<Value, String> {
    let project = server.project();
    let id = item_of(&params).ok_or("which item? pass its id as `item`")?;
    let said = params
        .get("text")
        .and_then(Value::as_str)
        .ok_or("pass the comment as `text`")?;
    project
        .items()
        .comment(&id, "agent", said, SystemTime::now())?;
    Ok(json!({ "item": id, "commented": true }))
}

pub fn start(server: &Server, params: Value) -> Result<Value, String> {
    let project = server.project();
    let id = item_of(&params).ok_or("which item? pass its id as `item`")?;
    let item = item_here(&project, &id)?;
    if item.closed.is_some() {
        return Err(format!(
            "item {id} is closed: {}",
            item.closed.as_ref().map(|c| c.word()).unwrap_or_default()
        ));
    }
    let blocking = super::gate::blocked_by(&project, &item);
    if !blocking.is_empty() {
        return Err(format!(
            "item {id} still waits on {}: finish those first",
            blocking.join(" and ")
        ));
    }
    project.items().set_state(&id, State::Doing)?;
    super::gate::keep_current(&project, &id)?;
    // Where the work began: what a later review diffs from.
    if let Ok(head) = devflow_engine::git::head_of(&project.root) {
        let _ = devflow_engine::started::keep_start(&project.runs(), &id, &head);
    }
    Ok(json!({
        "item": id,
        "state": "doing",
        "note": "Started. The hooks and the gate now hold this session to it.",
    }))
}

pub fn finish(server: &Server, params: Value) -> Result<Value, String> {
    let project = server.project();
    let id = item_of(&params).ok_or("which item? pass its id as `item`")?;
    item_here(&project, &id)?;
    super::gate::may_finish(server, &project, &id)?;
    let item = project.items().set_state(&id, State::Done)?;
    if let Some(note) = text(&params, "note") {
        project
            .items()
            .comment(&id, "agent", &note, SystemTime::now())?;
    }
    if super::gate::current(&project).as_deref() == Some(id.as_str()) {
        let _ = std::fs::remove_file(project.runs().home.join(super::gate::CURRENT));
    }
    Ok(json!({ "item": item.id, "state": "done" }))
}

pub fn handoff(server: &Server, params: Value) -> Result<Value, String> {
    let project = server.project();
    let id = item_of(&params).ok_or("which item? pass its id as `item`")?;
    item_here(&project, &id)?;
    let note = params.get("note").and_then(Value::as_str).ok_or(
        "pass where the work stands as `note`: what is done, what is left, what to read first",
    )?;
    project
        .items()
        .comment(&id, "handoff", note, SystemTime::now())?;
    Ok(json!({
        "item": id,
        "note": "Kept on the item: the next session reads it with `item`.",
    }))
}
