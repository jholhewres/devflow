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
    one(&project, asked)
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

/// The skills as MCP resources, `skill://devflow/<name>/SKILL.md`.
pub fn resources() -> Value {
    let resources: Vec<Value> = skills::described()
        .into_iter()
        .map(|(name, _, description)| {
            json!({
                "uri": skills::uri(name),
                "name": name,
                "description": description,
                "mimeType": "text/markdown",
            })
        })
        .collect();
    json!({ "resources": resources })
}

pub fn resource(project: &Project, params: &Value) -> Result<Value, String> {
    let uri = params
        .get("uri")
        .and_then(Value::as_str)
        .ok_or("pass the resource's `uri`")?;
    let skill = one(project, uri)?;
    Ok(json!({
        "contents": [{ "uri": uri, "mimeType": "text/markdown", "text": skill["text"] }],
    }))
}
