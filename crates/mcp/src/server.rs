//! `devflow mcp`: the flow as MCP tools, over stdio.
//!
//! Started by the agent CLI in the project's directory, which is how the
//! project is known. Newline-delimited JSON-RPC, which is what MCP's stdio
//! transport is.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use devflow_engine::Proposal;
use serde_json::{json, Value};

use crate::consent::Consent;
use crate::person::{Answer, Incoming, Person};
use crate::project::Project;
use crate::tools::{self, Tool};

/// The revisions this server speaks, newest first. A client asking for one
/// it does not know gets the newest.
pub const PROTOCOLS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// What a call needs to know: where it stands, the person's decisions, the
/// last setup this session showed them, and the line to ask them on.
pub struct Server {
    pub cwd: PathBuf,
    pub consent: Consent,
    pub preview: Mutex<Option<Proposal>>,
    pub person: Person,
}

impl Server {
    /// A server that never asks the person: a host's call or a hook.
    pub fn new(cwd: &Path) -> Server {
        Server {
            cwd: cwd.to_path_buf(),
            consent: Consent::of_user(),
            preview: Mutex::new(None),
            person: Person::none(),
        }
    }

    /// The project the call stands in, read again on each call.
    pub fn project(&self) -> Project {
        Project::at(&self.cwd)
    }

    /// Asks the person `message`, a form of `schema`, through the client.
    pub fn ask(&self, message: &str, schema: Value) -> Answer {
        self.person.ask(self, message, schema)
    }
}

/// Serves MCP on stdin/stdout until the client hangs up.
pub fn serve(root: &Path) -> i32 {
    let server = Server {
        person: Person::on_stdio(),
        ..Server::new(root)
    };
    loop {
        match server.person.received(None) {
            None => continue,
            Some(Incoming::Closed) => return 0,
            Some(Incoming::TooLong) => {
                server
                    .person
                    .send(&error(Value::Null, -32600, "that message is too long"));
            }
            Some(Incoming::Message(line)) => {
                if line.trim().is_empty() {
                    continue;
                }
                if let Some(answer) = handle(&line, &server) {
                    if !server.person.send(&answer) {
                        return 0;
                    }
                }
            }
        }
    }
}

/// One JSON-RPC message in, at most one out.
pub fn handle(line: &str, server: &Server) -> Option<String> {
    let Ok(message) = serde_json::from_str::<Value>(line) else {
        return Some(error(Value::Null, -32700, "that is not JSON"));
    };
    let method = message
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    // A notification has no id and gets no answer, whatever it says; nor
    // does a reply to a question no longer waited for.
    let id = message.get("id").cloned()?;
    if message.get("method").is_none()
        && (message.get("result").is_some() || message.get("error").is_some())
    {
        return None;
    }
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    let result = match method {
        "initialize" => {
            server
                .person
                .initialized(params.get("capabilities").unwrap_or(&Value::Null));
            server
                .person
                .introduced(params.get("clientInfo").unwrap_or(&Value::Null));
            json!({
            "protocolVersion": protocol(params.get("protocolVersion").and_then(Value::as_str)),
            "capabilities": { "tools": {}, "prompts": {}, "resources": {} },
            "serverInfo": { "name": "devflow", "version": env!("CARGO_PKG_VERSION") },
            "instructions": tools::INSTRUCTIONS,
            })
        }
        "ping" => json!({}),
        "tools/list" => json!({ "tools": tools::TOOLS.iter().map(listed).collect::<Vec<_>>() }),
        "tools/call" => call(&params, server),
        "prompts/list" => crate::flow::skill::prompts(),
        "resources/list" => crate::flow::skill::resources(),
        "resources/templates/list" => json!({ "resourceTemplates": [] }),
        "prompts/get" | "resources/read" => {
            let project = server.project();
            let answered = if method == "prompts/get" {
                crate::flow::skill::prompt(&project, &params)
            } else {
                crate::flow::skill::resource(&project, &params)
            };
            match answered {
                Ok(result) => result,
                Err(why) => return Some(error(id, -32602, &why)),
            }
        }
        _ => {
            return Some(error(
                id,
                -32601,
                &format!("devflow does not answer `{method}`"),
            ))
        }
    };
    Some(json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string())
}

/// The revision both sides speak.
pub fn protocol(asked: Option<&str>) -> &'static str {
    PROTOCOLS
        .iter()
        .find(|known| Some(**known) == asked)
        .unwrap_or(&PROTOCOLS[0])
}

fn listed(tool: &Tool) -> Value {
    json!({ "name": tool.name, "description": tool.description, "inputSchema": (tool.input)() })
}

/// A tool call. A refusal is the tool's error, not the protocol's: the agent
/// reads it and carries on.
fn call(params: &Value, server: &Server) -> Value {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(tool) = tools::TOOLS.iter().find(|tool| tool.name == name) else {
        return said(&format!("devflow has no tool `{name}`"), true);
    };
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    match (tool.call)(server, arguments) {
        // Compact: the text is read by a model, and indentation is a fifth of
        // a pretty answer's tokens.
        Ok(answer) => json!({
            "content": [{ "type": "text", "text": answer.to_string() }],
            "structuredContent": answer,
            "isError": false,
        }),
        Err(why) => said(&why, true),
    }
}

fn said(text: &str, failed: bool) -> Value {
    json!({ "content": [{ "type": "text", "text": text }], "isError": failed })
}

pub fn error(id: Value, code: i64, message: &str) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }).to_string()
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
