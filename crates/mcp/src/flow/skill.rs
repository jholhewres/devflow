//! `skill`: a stage's skill as the project resolves it — its own, a team
//! layer's, the person's, else the one devflow ships — and the skills listed
//! as MCP prompts and resources for clients without plugins.

use devflow_engine::skills;
use serde_json::{json, Value};

use crate::project::{self, Project};
use crate::server::Server;

pub fn skill(server: &Server, params: Value) -> Result<Value, String> {
    let project = server.project();
    let asked = ["name", "uri"]
        .iter()
        .find_map(|key| params.get(key).and_then(Value::as_str))
        .ok_or("pass the skill's `name`, such as devflow-plan")?;
    if let Some((skill, part)) = skills::part_named(asked) {
        return part_of(&project, skill, part);
    }
    match params.get("part").and_then(Value::as_str) {
        Some(part) => {
            let name =
                skills::named(asked).ok_or_else(|| format!("`{asked}` is not a devflow skill"))?;
            part_of(&project, name, part)
        }
        None => one(&project, asked),
    }
}

/// One part of a skill, as the project resolves it.
pub fn part_of(project: &Project, skill: &str, part: &str) -> Result<Value, String> {
    let teams = project.teams();
    let found = skills::resolve_part(
        &devflow_engine::Dialect::DEVFLOW,
        &skills::Words::default(),
        (&project.root, &project::personal_skills(), &teams),
        skill,
        part,
    )?;
    Ok(json!({
        "name": found.skill,
        "part": found.part,
        "uri": skills::part_uri(found.skill, found.part),
        "layer": found.layer.word(),
        "file": found.file.as_ref().map(|file| file.display().to_string()),
        "text": found.text,
    }))
}

/// One skill, by name or URI, with its text: any stage's, so a stage runs on
/// demand where devflow.yaml leaves it off.
pub fn one(project: &Project, asked: &str) -> Result<Value, String> {
    let name = skills::named(asked).ok_or_else(|| {
        format!(
            "`{asked}` is not a devflow skill: {}",
            skills::names().collect::<Vec<_>>().join(", ")
        )
    })?;
    let teams = project.teams();
    let skill = skills::resolve_with(&project.root, &project::personal_skills(), &teams, name)?;
    let mut said = skill.to_json();
    said["text"] = json!(skill.text);
    Ok(said)
}

/// The skills as MCP prompts: one per stage, its text the first message.
pub fn prompts() -> Value {
    let prompts: Vec<Value> = skills::described()
        .into_iter()
        .map(|(name, _, description)| json!({ "name": name, "description": description }))
        .collect();
    json!({ "prompts": prompts })
}

pub fn prompt(project: &Project, params: &Value) -> Result<Value, String> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or("pass the prompt's `name`")?;
    let skill = one(project, name)?;
    Ok(json!({
        "description": skill["frontmatter"]["description"],
        "messages": [{
            "role": "user",
            "content": { "type": "text", "text": skill["text"] },
        }],
    }))
}

/// The skills as MCP resources, `skill://devflow/<name>/SKILL.md`, and
/// their parts beside them.
pub fn resources() -> Value {
    let mut resources: Vec<Value> = Vec::new();
    for (name, _, description) in skills::described() {
        resources.push(json!({
            "uri": skills::uri(name),
            "name": name,
            "description": description,
            "mimeType": "text/markdown",
        }));
        for part in skills::parts(name) {
            resources.push(json!({
                "uri": skills::part_uri(name, part),
                "name": format!("{name}/{part}"),
                "description": format!("Part of {name}, loaded only when it says so."),
                "mimeType": "text/markdown",
            }));
        }
    }
    json!({ "resources": resources })
}

pub fn resource(project: &Project, params: &Value) -> Result<Value, String> {
    let uri = params
        .get("uri")
        .and_then(Value::as_str)
        .ok_or("pass the resource's `uri`")?;
    let skill = match skills::part_named(uri) {
        Some((name, part)) => part_of(project, name, part)?,
        None => one(project, uri)?,
    };
    Ok(json!({
        "contents": [{ "uri": uri, "mimeType": "text/markdown", "text": skill["text"] }],
    }))
}
