//! `devflow version --json` and `devflow host`, run as a host runs them: a
//! process, JSON on stdin and stdout.

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

#[test]
fn version_says_the_protocols_as_json() {
    let out = Command::new(env!("CARGO_BIN_EXE_devflow"))
        .args(["version", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let said: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        said,
        json!({ "version": env!("CARGO_PKG_VERSION"), "protocols": [1] })
    );
}

#[test]
fn a_host_call_initializes_writes_the_config_and_ends_when_stdin_closes() {
    let repo = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let file = repo.path().join(".devflow/devflow.yaml");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    let text = "# ours\nversion: 2\nenabled: false\nreview:\n  consolidate: none # for now\n";
    std::fs::write(&file, text).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_devflow"))
        .args(["host", "--root"])
        .arg(repo.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_STATE_HOME", home.path().join("state"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let calls = [
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": { "protocol": 1, "consent": { "enabled": false, "enforce": false } } }),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "config/write",
                "params": { "changes": [{ "path": "review.consolidate", "value": "agent" }] } }),
    ];
    let mut stdin = child.stdin.take().unwrap();
    for call in &calls {
        writeln!(stdin, "{call}").unwrap();
    }
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let replies: Vec<Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(replies.len(), 2, "{replies:?}");
    assert_eq!(replies[0]["result"]["methods"][0], "config/read");
    assert_eq!(replies[1]["result"]["changed"], true, "{}", replies[1]);
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        text.replace("consolidate: none #", "consolidate: agent #")
    );
    assert!(!home.path().join("state/devflow/update.lock").exists());
}

#[test]
fn a_line_that_is_not_utf8_is_answered_and_the_call_goes_on() {
    let repo = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_devflow"))
        .args(["host", "--root"])
        .arg(repo.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"\xff\xfe\n").unwrap();
    let call =
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocol": 1 } });
    writeln!(stdin, "{call}").unwrap();
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    let replies: Vec<Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(replies[0]["error"]["code"], -32700);
    assert_eq!(replies[1]["result"]["protocol"], 1);
}

#[test]
fn a_host_that_pins_its_folder_reads_and_writes_only_there() {
    let repo = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let ours = repo.path().join(".devpit/devflow/devflow.yaml");
    std::fs::create_dir_all(ours.parent().unwrap()).unwrap();
    let text = "version: 2\nreview:\n  consolidate: none\n";
    std::fs::write(&ours, text).unwrap();
    let other = repo.path().join("devflow.yaml");
    std::fs::write(&other, text).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_devflow"))
        .args(["host", "--root"])
        .arg(repo.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let calls = [
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": { "protocol": 1, "folder": ".devpit/devflow" } }),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "config/write",
                "params": { "changes": [{ "path": "review.consolidate", "value": "agent" }] } }),
    ];
    let mut stdin = child.stdin.take().unwrap();
    for call in &calls {
        writeln!(stdin, "{call}").unwrap();
    }
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    let replies: Vec<Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(replies[0]["result"]["folder"], ".devpit/devflow");
    assert_eq!(
        replies[1]["result"]["file"], ".devpit/devflow/devflow.yaml",
        "{}",
        replies[1]
    );
    assert!(std::fs::read_to_string(&ours)
        .unwrap()
        .contains("consolidate: agent"));
    assert_eq!(std::fs::read_to_string(&other).unwrap(), text);
}
