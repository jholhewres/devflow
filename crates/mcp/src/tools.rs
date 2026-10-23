//! The tools the server offers, each answered in this process from the
//! project's own files.

use serde_json::{json, Value};

use crate::server::Server;
use devflow_engine::Origin;

/// What the agent reads at the handshake.
pub const INSTRUCTIONS: &str = "devflow: an engineering flow (briefing, context, plan, execution, review, completion) whose work is done only when its evidence says so. Call `status` first.";

pub struct Tool {
    pub name: &'static str,
    pub description: &'static str,
    pub input: fn() -> Value,
    pub call: fn(&Server, Value) -> Result<Value, String>,
}

pub static TOOLS: [Tool; 1] = [Tool {
    name: "status",
    description: "devflow in this project: whether it has a configuration and which file it is (devflow.yaml, .devflow/devflow.yaml, or devpit's .devpit/devflow/devflow.yaml read where it is). Read it first.",
    input: || json!({ "type": "object", "properties": {} }),
    call: status,
}];

fn status(server: &Server, _: Value) -> Result<Value, String> {
    Ok(status_of(&server.root))
}

/// The `status` answer for a project's root.
pub fn status_of(root: &std::path::Path) -> Value {
    match devflow_engine::config_in(root) {
        None => json!({
            "state": "none",
            "looked_for": devflow_engine::locate::CANDIDATES,
        }),
        Some(found) => json!({
            "state": "found",
            "path": found.path,
            "layout": match found.origin {
                Origin::Root => "root",
                Origin::Folder => "folder",
                Origin::Devpit => "devpit",
            },
        }),
    }
}
