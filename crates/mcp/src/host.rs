//! `devflow host`: one call from a host app over stdio. JSON-RPC 2.0, one
//! object per line: the host sends `initialize`, then a method, and closes
//! stdin; stderr carries logs only. The host keeps its own record of the
//! person's two switches and passes it in; nothing here updates the binary.

use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Mutex;

use devflow_engine::folder::{self, State};
use devflow_engine::{proposal, security, setup};
use serde_json::{json, Value};

use crate::consent::Consent;
use crate::server::Server;

/// The host protocols this devflow speaks.
pub const PROTOCOLS: [u64; 1] = [1];
/// The methods served after `initialize`.
pub const METHODS: [&str; 4] = ["config/read", "config/write", "tool", "shutdown"];
/// The tools `tool` serves.
pub const TOOLS: [&str; 1] = ["status"];

const MOST_LINE_BYTES: usize = 8 * 1024 * 1024;
const PARSE: i64 = -32700;
const REQUEST: i64 = -32600;
const NO_METHOD: i64 = -32601;
const PARAMS: i64 = -32602;
const FAILED: i64 = -32000;
const NOT_STARTED: i64 = -32002;

type Failed = (i64, String);

/// What `initialize` set up.
pub struct Session {
    pub server: Server,
}

/// What one message is answered with, and whether the call ends there.
pub struct Answer {
    pub reply: Option<String>,
    pub last: bool,
}

pub fn run(root: &Path) -> ExitCode {
    let mut session = None;
    let mut stdin = std::io::stdin().lock();
    let mut line = String::new();
    loop {
        line.clear();
        match (&mut stdin)
            .take(MOST_LINE_BYTES as u64 + 1)
            .read_line(&mut line)
        {
            Ok(0) | Err(_) => return ExitCode::SUCCESS,
            Ok(read) if read > MOST_LINE_BYTES => {
                send(&error(Value::Null, REQUEST, "that message is too long"));
                return ExitCode::FAILURE;
            }
            Ok(_) => {}
        }
        if line.trim().is_empty() {
            continue;
        }
        let answer = answer(&line, root, &mut session);
        if let Some(reply) = answer.reply {
            if !send(&reply) {
                return ExitCode::FAILURE;
            }
        }
        if answer.last {
            return ExitCode::SUCCESS;
        }
    }
}

fn send(message: &str) -> bool {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{message}")
        .and_then(|()| out.flush())
        .is_ok()
}

fn error(id: Value, code: i64, message: &str) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }).to_string()
}

/// One message in, at most one out.
pub fn answer(line: &str, root: &Path, session: &mut Option<Session>) -> Answer {
    let reply = |text: String, last: bool| Answer {
        reply: Some(text),
        last,
    };
    let Ok(message) = serde_json::from_str::<Value>(line) else {
        return reply(error(Value::Null, PARSE, "that is not JSON"), false);
    };
    let Some(method) = message.get("method").and_then(Value::as_str) else {
        return reply(
            error(Value::Null, REQUEST, "a request names its method"),
            false,
        );
    };
    // A notification has no id and gets no answer.
    let Some(id) = message.get("id").cloned() else {
        return Answer {
            reply: None,
            last: false,
        };
    };
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    let result = match (method, session.as_ref()) {
        ("initialize", _) => initialize(&params, root).map(|(started, said)| {
            *session = Some(started);
            said
        }),
        (_, None) if METHODS.contains(&method) => {
            Err((NOT_STARTED, "initialize comes first".to_owned()))
        }
        ("config/read", Some(started)) => Ok(read(&started.server)),
        ("config/write", Some(started)) => write(&started.server, &params),
        ("tool", Some(started)) => tool(&started.server, &params),
        ("shutdown", Some(_)) => {
            return reply(
                json!({ "jsonrpc": "2.0", "id": id, "result": {} }).to_string(),
                true,
            )
        }
        _ => Err((
            NO_METHOD,
            format!(
                "method not found: devflow {} serves {}",
                env!("CARGO_PKG_VERSION"),
                METHODS.join(", ")
            ),
        )),
    };
    let text = match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string(),
        Err((code, why)) => error(id, code, &why),
    };
    reply(text, false)
}

fn initialize(params: &Value, root: &Path) -> Result<(Session, Value), Failed> {
    let asked = params.get("protocol").and_then(Value::as_u64);
    let Some(protocol) = asked.filter(|asked| PROTOCOLS.contains(asked)) else {
        return Err((
            PARAMS,
            format!(
                "devflow {} speaks protocols {PROTOCOLS:?}; the host asked for {}",
                env!("CARGO_PKG_VERSION"),
                params.get("protocol").unwrap_or(&Value::Null)
            ),
        ));
    };
    let root = params
        .get("root")
        .and_then(Value::as_str)
        .map_or_else(|| root.to_path_buf(), PathBuf::from);
    if !root.is_dir() {
        return Err((PARAMS, format!("{} is not a folder", root.display())));
    }
    let switch = |name: &str| params["consent"][name].as_bool().unwrap_or(false);
    let server = Server {
        cwd: root,
        consent: Consent::of_user().switched_by_host(switch("enabled"), switch("enforce")),
        preview: Mutex::new(None),
    };
    let said = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": protocol,
        "methods": METHODS,
        "tools": TOOLS,
    });
    Ok((Session { server }, said))
}

/// The configuration as the file says it, valid or not.
fn said(state: &State) -> Value {
    match state {
        State::Valid(_, config) => config.to_json(),
        State::Invalid(Some(text), _) => folder::as_json(text).unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

/// `config/read`: the project's devflow.yaml, its layers, and the targets
/// in force.
pub fn read(server: &Server) -> Value {
    let project = server.project();
    let own = folder::read(&project.root);
    let layered = project.read();
    let mut answer = json!({
        "state": match &layered {
            State::Missing => "missing",
            State::Invalid(..) => "invalid",
            State::Valid(..) => "valid",
        },
        "file": project.layout().file,
        "config": said(&own),
        "unread": [],
        "layered": { "teams": [], "stages_from": Value::Null },
        "security": { "targets_in_force": [] },
    });
    match (&own, &layered) {
        (_, State::Invalid(_, invalid)) => answer["invalid"] = json!(invalid),
        (State::Valid(text, _), State::Valid(_, config)) => {
            answer["unread"] = json!(devflow_engine::config::unread(text));
            answer["security"]["targets_in_force"] = json!(crate::flow::targets_in_force(
                &project,
                config,
                &server.consent
            ));
        }
        _ => {}
    }
    if let Some(layers) = project.layered() {
        answer["layered"] = json!({ "teams": layers.teams, "stages_from": layers.stages_from });
    }
    answer
}

/// `config/write`: fields of devflow.yaml changed in its text, its comments
/// and the fields devflow does not read kept. `by: "person"` is the person's
/// own click, which alone raises `enabled` and `decisions.mode: enforce`.
pub fn write(server: &Server, params: &Value) -> Result<Value, Failed> {
    let mut changes = Vec::new();
    for change in params["changes"].as_array().into_iter().flatten() {
        let path = change["path"]
            .as_str()
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .ok_or((PARAMS, "each change names its `path`".to_owned()))?;
        if security::persons_only(path) {
            return Err((PARAMS, security::PERSONS_ONLY.to_owned()));
        }
        changes.push((path.to_owned(), change["value"].clone()));
    }
    if changes.is_empty() {
        return Err((PARAMS, "pass `changes`: [{path, value}]".to_owned()));
    }
    let person = params["by"] == "person";
    let project = server.project();
    let layout = project.layout();
    let state = folder::read_in(layout.dialect, &project.root);
    let failed = |why: String| (FAILED, why);
    let proposal = proposal::set_all_in(&layout, &state, &changes, person)
        .map_err(|invalid| failed(invalid.to_string()))?;
    if proposal.laid_out {
        return Err(failed(format!(
            "{} cannot be edited in place for this change, so nothing was written: edit it by \
             hand, or write it as a flow-style map no longer",
            layout.file
        )));
    }
    let changed = !proposal.changes.is_empty();
    if changed {
        devflow_engine::layers::layered(&project.root, &proposal.yaml, &crate::project::home())
            .map_err(|invalid| failed(invalid.to_string()))?;
        let planned = setup::with_unused(&project.root, &proposal.config, proposal.files.clone());
        setup::write(&project.root, &planned).map_err(failed)?;
    }
    Ok(json!({
        "changed": changed,
        "file": layout.file,
        "laid_out": false,
        "before": said(&state),
        "after": proposal.config.to_json(),
        "asks": proposal.asks,
    }))
}

/// `tool`: one of the flow's tools, answered as `devflow mcp` answers it.
fn tool(server: &Server, params: &Value) -> Result<Value, Failed> {
    let name = params["name"].as_str().unwrap_or_default();
    match name {
        "status" => Ok(crate::flow::setup::status_of(&server.project(), server)),
        _ if crate::tools::TOOLS.iter().any(|tool| tool.name == name) => Err((
            NO_METHOD,
            format!(
                "the tool `{name}` is not served over host by devflow {}: {}",
                env!("CARGO_PKG_VERSION"),
                TOOLS.join(", ")
            ),
        )),
        _ => Err((PARAMS, format!("there is no tool `{name}`"))),
    }
}

#[cfg(test)]
#[path = "host_tests.rs"]
mod tests;
