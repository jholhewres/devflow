//! While a long tool call runs, `devflow mcp` still answers `ping`, says the
//! call's progress to a client that asked for it, and ends the call's
//! processes when the client cancels it.

mod common;

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

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

/// A project with devflow on, two checks (one that takes a few seconds and
/// one that would take minutes, writing its pid first) and an item started.
fn started(mcp: &mut Mcp, root: &Path, home: &Path, pid_at: &Path) -> String {
    git(root, &["init", "-q", "--initial-branch=main"]);
    git(root, &["config", "user.email", "test@example.invalid"]);
    git(root, &["config", "user.name", "Test"]);
    git(root, &["config", "commit.gpgsign", "false"]);
    std::fs::write(root.join("README.md"), "# shop\n").unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "first"]);
    mcp.ask("initialize", json!({ "protocolVersion": "2025-06-18" }));
    let set = json!({ "stages.execution.checks": [
        { "name": "slow", "run": "sleep 3" },
        { "name": "stuck", "run": format!("sh -c 'echo $$ > {}; exec sleep 300'", pid_at.display()) },
    ] });
    let preview = mcp.call("setup", json!({ "preset": "custom", "set": set }));
    assert_eq!(preview["applied"], false, "{preview}");
    let applied = mcp.call(
        "setup",
        json!({ "preset": "custom", "set": set, "apply": true }),
    );
    assert_eq!(applied["applied"], true, "{applied}");
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
        "criteria": ["rename changes the title"], "verify": "sleep 3" }]);
    mcp.call("plan", json!({ "epic": epic, "items": items }));
    let made = mcp.call("plan", json!({ "epic": epic, "apply": true }));
    let item = made["starts_now"][0].as_str().unwrap().to_owned();
    mcp.call("start", json!({ "item": item }));
    item
}

#[cfg(unix)]
#[test]
fn a_long_call_answers_ping_says_its_progress_and_stops_when_cancelled() {
    let repo = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let root = repo.path().canonicalize().unwrap();
    let pid_at = home.path().join("stuck.pid");
    let mut mcp = Mcp::start(&root, home.path());
    let item = started(&mut mcp, &root, home.path(), &pid_at);

    // A ping while the checks run is answered before the call ends, and
    // the client that gave a token hears each check done.
    mcp.say(
        json!({ "jsonrpc": "2.0", "id": 100, "method": "tools/call", "params": {
        "name": "evidence", "arguments": { "item": item, "checks": ["slow"], "fresh": true },
        "_meta": { "progressToken": "p1" } } }),
    );
    mcp.say(json!({ "jsonrpc": "2.0", "id": 101, "method": "ping" }));
    let mut heard: Vec<Value> = Vec::new();
    loop {
        let message = mcp.heard();
        let done = message["id"] == 100;
        heard.push(message);
        if done {
            break;
        }
    }
    let at = |id: i64| heard.iter().position(|one| one["id"] == id);
    assert!(
        at(101).expect("pong") < at(100).expect("result"),
        "{heard:#?}"
    );
    assert_eq!(heard[at(101).unwrap()]["result"], json!({}));
    let progress: Vec<&Value> = heard
        .iter()
        .filter(|one| one["method"] == "notifications/progress")
        .collect();
    assert!(!progress.is_empty(), "{heard:#?}");
    assert_eq!(progress[0]["params"]["progressToken"], "p1");
    assert_eq!(progress[0]["params"]["progress"], 1);

    // Cancelled, the call's check is ended and the call says so.
    mcp.say(
        json!({ "jsonrpc": "2.0", "id": 200, "method": "tools/call", "params": {
        "name": "evidence", "arguments": { "item": item, "checks": ["stuck"], "fresh": true } } }),
    );
    let began = Instant::now();
    while !pid_at.exists() && began.elapsed() < Duration::from_secs(20) {
        std::thread::sleep(Duration::from_millis(50));
    }
    let pid = std::fs::read_to_string(&pid_at).expect("the check started");
    let pid = pid.trim().to_owned();
    mcp.say(
        json!({ "jsonrpc": "2.0", "method": "notifications/cancelled",
        "params": { "requestId": 200, "reason": "the person stopped it" } }),
    );
    let answer = loop {
        let message = mcp.heard();
        if message["id"] == 200 {
            break message;
        }
    };
    assert!(
        began.elapsed() < Duration::from_secs(60),
        "ended well before its 300 s"
    );
    assert_eq!(answer["result"]["isError"], true, "{answer}");
    assert!(answer["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("cancelled"));
    let alive = Command::new("kill")
        .args(["-0", &pid])
        .output()
        .is_ok_and(|out| out.status.success());
    assert!(!alive, "the check's process {pid} was ended");

    // The next call is not cancelled by the last one's.
    let next = mcp.ask("tools/call", json!({ "name": "status", "arguments": {} }));
    assert_eq!(next["result"]["isError"], false, "{next}");
}
