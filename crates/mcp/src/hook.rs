//! `devflow hook <event>`: what an agent CLI's hook runs. A Stop is
//! answered by the gate on the session's work item, a session's start with
//! that item's context, each as the CLI reads a hook's reply on stdout.
//! Nothing is said where devflow is off, and a payload that does not read
//! lets the turn end as it would have.

use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

use serde_json::{json, Value};

use crate::flow::gate;
use crate::server::Server;

/// The most of a hook's payload read.
const MOST_PAYLOAD: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Event {
    Stop,
    SubagentStop,
    SessionStart,
}

pub fn run(event: Event, agent: &str, root: &Path) -> ExitCode {
    let mut raw = String::new();
    let _ = std::io::stdin().take(MOST_PAYLOAD).read_to_string(&mut raw);
    let payload: Value = serde_json::from_str(&raw).unwrap_or_else(|_| json!({}));
    // The CLI says where the session stands (Cursor, its workspace's
    // roots); else where the hook runs.
    let cwd = payload["cwd"]
        .as_str()
        .or_else(|| payload["workspace_roots"][0].as_str())
        .map(std::path::PathBuf::from)
        .filter(|cwd| cwd.is_dir())
        .unwrap_or_else(|| root.to_path_buf());
    let server = Server::new(&cwd);
    if let Some(said) = answered(&server, event, agent, &payload) {
        println!("{said}");
    }
    ExitCode::SUCCESS
}

/// The hook's reply, or nothing.
pub fn answered(server: &Server, event: Event, agent: &str, payload: &Value) -> Option<String> {
    match event {
        Event::SessionStart => {
            let project = server.project();
            let said = gate::session_context(server, &project, agent)?;
            Some(
                json!({ "hookSpecificOutput": { "hookEventName": "SessionStart", "additionalContext": said } })
                    .to_string(),
            )
        }
        // A turn the person stopped, or that failed, is not sent back.
        Event::Stop | Event::SubagentStop
            if agent == "cursor"
                && payload["status"]
                    .as_str()
                    .is_some_and(|status| status != "completed") =>
        {
            None
        }
        Event::Stop | Event::SubagentStop => {
            let mut payload = payload.clone();
            // Cursor names its events in its own case (`stop`).
            if payload["hook_event_name"].is_null() || agent == "cursor" {
                payload["hook_event_name"] = json!(match event {
                    Event::SubagentStop => "SubagentStop",
                    _ => "Stop",
                });
            }
            let cap = std::env::var(devflow_engine::gate::CAP_ENV).ok();
            let params = gate::hook_params(&payload, agent, cap);
            let reply = said_as(agent, gate::gate(server, params).ok()?)?;
            (reply.as_object().is_some_and(|fields| !fields.is_empty())).then(|| reply.to_string())
        }
    }
}

/// The gate's reply as `agent` reads a stop hook's: Cursor sends a turn
/// back with `followup_message` and has no note to show; Claude Code and
/// Codex read the reply as it is.
fn said_as(agent: &str, reply: Value) -> Option<Value> {
    if agent != "cursor" {
        return Some(reply);
    }
    match reply["reason"].as_str() {
        Some(reason) if reply["decision"] == "block" => Some(json!({ "followup_message": reason })),
        _ => Some(json!({})),
    }
}

#[cfg(test)]
#[path = "hook_tests.rs"]
mod tests;
