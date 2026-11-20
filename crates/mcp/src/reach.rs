//! Whether devflow's server reaches every Claude Code session. The devflow
//! plugin brings it, but a session that loads another plugin named devflow
//! (`claude --plugin-dir`, as devpit starts its sessions) hides that plugin,
//! and the server with it. The same server in the person's Claude Code user
//! config reaches every session, and Claude Code then leaves the plugin's
//! copy out. `status` tells Claude Code so, and offers to put it there once:
//! it is put there on the person's yes to the question asked through the
//! client, never on a tool's arguments.

use std::path::PathBuf;
use std::time::Duration;

use serde_json::{json, Value};

use crate::doctor::CLAUDE_FIX;
use crate::person::Answer;
use crate::register::{self, Step, UserServer};
use crate::server::Server;

/// The name Claude Code gives itself in `initialize`.
pub const CLIENT: &str = "claude-code";
/// The offer, as consent.json keeps the person's no to it.
pub const OFFER: &str = "claude-user-server";
/// How long one `claude mcp` command may take.
const WAIT: Duration = Duration::from_secs(60);

/// Runs one command; why it failed.
pub type Runner = Box<dyn Fn(&[String]) -> Result<(), String>>;

/// Claude Code on this machine: where it keeps its user config, and how a
/// command of its is run.
pub struct Claude {
    pub dir: PathBuf,
    pub run: Runner,
}

impl Claude {
    pub fn here() -> Claude {
        Claude {
            dir: register::Machine::here().claude,
            run: Box::new(quietly),
        }
    }
}

/// Runs a command with nothing of it reaching the client's line, which is
/// this process's stdout, and nothing asked on stdin.
fn quietly(argv: &[String]) -> Result<(), String> {
    let words: Vec<&str> = argv.iter().map(String::as_str).collect();
    register::asked_within(&words, WAIT)
        .map(|_| ())
        .ok_or_else(|| format!("`{}` failed", argv.join(" ")))
}

/// What `status` says to Claude Code when devflow's server is not in its
/// user config, after offering, once, to put it there; `None` for another
/// client, or when it is there.
pub fn offered(server: &Server, claude: &Claude) -> Option<Value> {
    if server.person.client().as_deref() != Some(CLIENT) {
        return None;
    }
    let now = register::user_server(&claude.dir);
    let note = match &now {
        UserServer::Same => return None,
        UserServer::Missing => "devflow's server reaches this Claude Code session only through \
             the devflow plugin: a session that loads another plugin named devflow (`claude \
             --plugin-dir`, as devpit starts its sessions) hides that plugin, and has no devflow \
             tools. In the person's Claude Code user config it reaches every session, and the \
             plugin's copy steps aside."
            .to_owned(),
        UserServer::Other(runs) => format!(
            "The person's Claude Code user config has a devflow server that runs `{runs}`, not \
             `devflow mcp`, so Claude Code keeps it beside the plugin's and each devflow tool \
             shows twice."
        ),
    };
    let mut said = json!({ "user_config": false, "note": note, "fix": CLAUDE_FIX });
    if server.consent.declined(OFFER) || !server.person.offer_once() {
        return Some(said);
    }
    let asked = match server.ask(QUESTION, schema()) {
        Answer::Accepted(content) if content.get("add") == Some(&Value::Bool(true)) => {
            match put(&now, claude) {
                Ok(()) => {
                    said["user_config"] = json!(true);
                    said["note"] = json!(
                        "The person put devflow's server in their Claude Code user config: \
                         sessions started from now on have it, whatever plugins they load."
                    );
                    "added".to_owned()
                }
                Err(why) => format!("failed: {why}"),
            }
        }
        Answer::Accepted(_) | Answer::Declined => match server.consent.decline(OFFER) {
            Ok(()) => "declined: not offered again on this machine".to_owned(),
            Err(why) => format!("declined, but it could not be kept: {why}"),
        },
        Answer::Cancelled => "dismissed".to_owned(),
        Answer::Unasked(why) => format!("not asked: {why}"),
    };
    said["asked"] = json!(asked);
    Some(said)
}

const QUESTION: &str = "devflow's server reaches Claude Code only through the devflow plugin, so \
    a session that loads another plugin named devflow (as devpit starts its sessions) has no \
    devflow tools. Put it in your Claude Code user config, so every session has it? It runs \
    `claude mcp add --scope user devflow -- devflow mcp`; where the plugin is loaded too, Claude \
    Code keeps one of the two.";

fn schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "add": {
                "type": "boolean",
                "title": "Put devflow's server in my Claude Code user config",
                "default": true,
            },
        },
        "required": ["add"],
    })
}

/// Puts devflow's server in Claude Code's user config, as `devflow register`
/// would. One that ran something else is taken out first: when the new one
/// then fails, the answer says so.
fn put(now: &UserServer, claude: &Claude) -> Result<(), String> {
    let mut removed = false;
    for step in register::claude_server(now) {
        let Step::Run(argv) = step else { continue };
        if let Err(why) = (claude.run)(&argv) {
            return Err(match now {
                UserServer::Other(runs) if removed => format!(
                    "{why}; the devflow server that ran `{runs}` was taken out: \
                     `{CLAUDE_FIX}` puts devflow's in"
                ),
                _ => why,
            });
        }
        removed = argv.get(2).is_some_and(|word| word == "remove");
    }
    Ok(())
}

#[cfg(test)]
#[path = "reach_tests.rs"]
mod tests;
