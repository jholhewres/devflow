//! The Stop hook `devflow register` installs in Codex and Cursor sends a
//! turn back while the gate fails, each in the shape its CLI reads: Codex
//! as Claude Code (`decision: block`), Cursor with `followup_message`. A
//! turn the person stopped in Cursor is let go.

mod common;

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use common::Mcp;

use serde_json::{json, Value};

fn git(repo: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .unwrap()
        .status
        .success();
    assert!(ok, "git {args:?}");
}

/// A project with devflow on and an item started, whose gate fails: no
/// evidence yet.
fn started(root: &Path, home: &Path) {
    git(root, &["init", "-q", "--initial-branch=main"]);
    git(root, &["config", "user.email", "test@example.invalid"]);
    git(root, &["config", "user.name", "Test"]);
    git(root, &["config", "commit.gpgsign", "false"]);
    std::fs::write(root.join("README.md"), "# shop\n").unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "first"]);
    let mut mcp = Mcp::start(root, home);
    mcp.ask("initialize", json!({ "protocolVersion": "2025-06-18" }));
    let set = json!({ "stages.execution.checks": [{ "name": "unit", "run": "true" }] });
    mcp.call("setup", json!({ "preset": "custom", "set": set }));
    mcp.call(
        "setup",
        json!({ "preset": "custom", "set": set, "apply": true }),
    );
    let yaml = std::fs::read_to_string(root.join(".devflow/devflow.yaml")).unwrap();
    std::fs::write(
        root.join(".devflow/devflow.yaml"),
        yaml.replace("enabled: false", "enabled: true"),
    )
    .unwrap();
    std::fs::create_dir_all(home.join("config/devflow")).unwrap();
    std::fs::write(
        home.join("config/devflow/consent.json"),
        json!({ "enabled": [root.display().to_string()] }).to_string(),
    )
    .unwrap();
    let epic = mcp.call(
        "brief",
        json!({ "title": "Rename", "goal": "Products can be renamed", "success": "the title changes", "out_of_scope": ["prices"] }),
    );
    let epic = epic["item"].as_str().unwrap().to_owned();
    let items = json!([{ "key": "s1", "title": "Rename changes the title", "build": "A rename.",
        "criteria": ["rename changes the title"], "verify": "true" }]);
    mcp.call("plan", json!({ "epic": epic, "items": items }));
    let made = mcp.call("plan", json!({ "epic": epic, "apply": true }));
    let item = made["starts_now"][0].as_str().unwrap().to_owned();
    mcp.call("start", json!({ "item": item }));
}

/// What `devflow hook stop --agent <agent>` prints for `payload`, run
/// where `cwd` is.
fn stop(agent: &str, payload: Value, cwd: &Path, home: &Path) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_devflow"))
        .args(["hook", "stop", "--agent", agent])
        .current_dir(cwd)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env_remove("CLAUDE_CODE_STOP_HOOK_BLOCK_CAP")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{payload}").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

#[cfg(unix)]
#[test]
fn codex_and_cursor_turns_are_sent_back_while_the_gate_fails() {
    let repo = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let root = repo.path().canonicalize().unwrap();
    started(&root, home.path());
    let elsewhere = home.path();

    // Codex pipes Claude Code's payload, and reads its reply.
    let codex = stop(
        "codex",
        json!({ "session_id": "s1", "cwd": root, "hook_event_name": "Stop",
            "turn_id": "t1", "stop_hook_active": false, "transcript_path": null }),
        elsewhere,
        home.path(),
    );
    let said: Value = serde_json::from_str(&codex).unwrap_or_else(|_| panic!("{codex}"));
    assert_eq!(said["decision"], "block", "{said}");
    assert!(said["reason"]
        .as_str()
        .is_some_and(|reason| !reason.is_empty()));

    // Cursor names its session a conversation and its folder a workspace
    // root, and continues a turn by a follow-up message.
    let cursor = stop(
        "cursor",
        json!({ "conversation_id": "c1", "generation_id": "g1", "status": "completed",
            "loop_count": 0, "hook_event_name": "stop", "workspace_roots": [root] }),
        elsewhere,
        home.path(),
    );
    let said: Value = serde_json::from_str(&cursor).unwrap_or_else(|_| panic!("{cursor}"));
    assert!(
        said["followup_message"]
            .as_str()
            .is_some_and(|said| !said.is_empty()),
        "{said}"
    );
    assert!(said.get("decision").is_none(), "{said}");

    // A turn the person stopped is let go.
    let aborted = stop(
        "cursor",
        json!({ "conversation_id": "c2", "status": "aborted", "loop_count": 0,
            "hook_event_name": "stop", "workspace_roots": [root] }),
        elsewhere,
        home.path(),
    );
    assert_eq!(aborted, "");
}
