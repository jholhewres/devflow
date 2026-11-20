//! The attack stage over MCP and on the command line: on an item whose diff
//! touches a sensitive path, the gate holds it until the attack ran; the
//! attack keeps its report in the item's run, and what the session's run of
//! an exploit confirmed holds the item until its test is green.

mod common;

use std::path::Path;
use std::process::Command;

use common::Mcp;
use serde_json::json;

fn git(repo: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .args(args)
        .current_dir(repo)
        .status()
        .unwrap()
        .success();
    assert!(ok, "git {args:?}");
}

#[cfg(unix)]
fn fake_claude(bin: &Path, answer: &serde_json::Value) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(bin).unwrap();
    let envelope = json!({ "type": "result", "result": answer.to_string(), "total_cost_usd": 0.5 });
    std::fs::write(bin.join("answer.json"), envelope.to_string()).unwrap();
    let script = bin.join("claude");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\ncat > /dev/null\ncat '{}/answer.json'\n",
            bin.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn an_item_on_a_sensitive_path_is_held_until_its_attack_ran_and_its_hole_is_shut() {
    let repo = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let root = repo.path().canonicalize().unwrap();
    git(&root, &["init", "-q", "--initial-branch=main"]);
    git(&root, &["config", "user.email", "test@example.invalid"]);
    git(&root, &["config", "user.name", "Test"]);
    git(&root, &["config", "commit.gpgsign", "false"]);
    std::fs::create_dir_all(root.join(".devflow")).unwrap();
    std::fs::write(
        root.join(".devflow/devflow.yaml"),
        "version: 2\nenabled: true\nstages:\n  - uses: builtin/execution\n    checks:\n      - { name: unit, run: \"true\", report: none }\n  - uses: builtin/review\n    enabled: false\n  - uses: builtin/attack\n    run: sensitive\n  - uses: builtin/completion\n",
    )
    .unwrap();
    std::fs::write(root.join("README.md"), "# shop\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "first"]);
    std::fs::create_dir_all(home.path().join("config/devflow")).unwrap();
    std::fs::write(
        home.path().join("config/devflow/consent.json"),
        json!({ "enabled": [root.display().to_string()] }).to_string(),
    )
    .unwrap();
    let bin = home.path().join("bin");
    fake_claude(
        &bin,
        &json!({ "version": 1, "hypotheses": [{
            "id": "h1", "title": "a cookie signed with any key is accepted", "file": "src/auth/session.rs",
            "line": 1, "severity": "high", "status": "tried", "reason": "the signature is never checked",
            "exploit": { "path": "tests/session.exploit.sh", "test": "forged-cookie", "code": "exit 1" },
        }] }),
    );
    let mut mcp = Mcp::start_with(&root, home.path(), Some(&bin));
    mcp.ask("initialize", json!({ "protocolVersion": "2025-06-18" }));
    let tools = mcp.ask("tools/list", json!({}));
    assert!(
        tools.to_string().contains("\"attack\""),
        "the attack tool is offered"
    );

    let item = mcp.call("item", json!({ "title": "Sessions", "body": "## Acceptance criteria\n- [ ] a forged cookie is refused\n" }));
    let item = item["id"].as_str().unwrap().to_owned();
    mcp.call("start", json!({ "item": item }));
    std::fs::create_dir_all(root.join("src/auth")).unwrap();
    std::fs::write(root.join("src/auth/session.rs"), "fn check() {}\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "sessions"]);
    mcp.call("evidence", json!({ "item": item, "criteria": [{ "criterion": "a forged cookie is refused", "tests": ["forged-cookie"] }] }));

    let held = mcp.call("gate", json!({ "item": item }));
    assert!(
        held.to_string().contains("attack stage has not run"),
        "{held}"
    );

    let attacked = mcp.call("attack", json!({ "item": item }));
    let run = attacked["run"].as_str().unwrap().to_owned();
    assert_eq!(attacked["counts"]["tried"], 1, "{attacked}");
    let report = root.join(format!(".devflow/runs/{item}/{run}/attack.json"));
    assert!(report.is_file(), "{}", report.display());
    let files = attacked["files"].to_string();
    for file in [
        "attack-report.md",
        "attack-report.json",
        "attack-report.sarif",
    ] {
        assert!(files.contains(file), "{file} named: {files}");
    }
    assert!(
        !root.join("tests/session.exploit.sh").exists(),
        "never the checkout"
    );

    let confirmed = mcp.call(
        "attack",
        json!({ "item": item, "run": run, "verified": [{ "hypothesis": "h1", "result": "confirmed", "evidence": "red", "test": "forged-cookie" }] }),
    );
    assert_eq!(confirmed["verdict"], "request_changes", "{confirmed}");
    let held = mcp.call("gate", json!({ "item": item }));
    assert!(
        held.to_string()
            .contains("the exploit test `forged-cookie`"),
        "{held}"
    );
    let status = mcp.call("status", json!({}));
    assert_eq!(status["attack"]["runs"], 1, "{status}");
    assert_eq!(
        status["attack"]["confirmed"], 1,
        "the session's run counted: {status}"
    );
    assert!(mcp
        .refused("attack", json!({ "item": item, "prove": true }))
        .contains("`run`"));
    let unproven = mcp.refused("attack", json!({ "item": item, "run": run, "prove": true }));
    assert!(unproven.contains("stages.attack.test"), "{unproven}");
    drop(mcp);

    let said = Command::new(env!("CARGO_BIN_EXE_devflow"))
        .args(["--root", &root.display().to_string(), "attack", &item])
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_CACHE_HOME", home.path().join("cache"))
        .env("DEVFLOW_NO_UPDATE", "1")
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .output()
        .unwrap();
    assert!(
        said.status.success(),
        "{}",
        String::from_utf8_lossy(&said.stderr)
    );
    let answer: serde_json::Value = serde_json::from_slice(&said.stdout).unwrap();
    assert_eq!(answer["counts"]["tried"], 1, "{answer}");
    let sarif = Command::new(env!("CARGO_BIN_EXE_devflow"))
        .args([
            "--root",
            &root.display().to_string(),
            "attack",
            &item,
            "--report",
            &run,
            "--format",
            "sarif",
        ])
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_CACHE_HOME", home.path().join("cache"))
        .env("DEVFLOW_NO_UPDATE", "1")
        .output()
        .unwrap();
    let sarif: serde_json::Value = serde_json::from_slice(&sarif.stdout).unwrap();
    assert_eq!(sarif["version"], "2.1.0", "{sarif}");
    assert_eq!(
        sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
            ["uri"],
        "src/auth/session.rs"
    );
    std::fs::create_dir_all(root.join(".devflow/reviewers")).unwrap();
    std::fs::write(
        root.join(".devflow/reviewers/devflow-security.overlay.md"),
        "Sessions are the asset.",
    )
    .unwrap();
    let shown = Command::new(env!("CARGO_BIN_EXE_devflow"))
        .args([
            "--root",
            &root.display().to_string(),
            "persona",
            "show",
            "devflow-security",
        ])
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("DEVFLOW_NO_UPDATE", "1")
        .output()
        .unwrap();
    let shown = String::from_utf8_lossy(&shown.stdout);
    assert!(
        shown.starts_with(&format!("devflow {}", env!("CARGO_PKG_VERSION"))),
        "{shown}"
    );
    assert!(
        shown.contains("devflow-security.overlay.md (sha256:"),
        "{shown}"
    );
    assert!(
        shown.trim_end().ends_with("Sessions are the asset."),
        "{shown}"
    );
    let numbers = Command::new(env!("CARGO_BIN_EXE_devflow"))
        .args(["--root", &root.display().to_string(), "status", "--attack"])
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_CACHE_HOME", home.path().join("cache"))
        .env("DEVFLOW_NO_UPDATE", "1")
        .output()
        .unwrap();
    let numbers: serde_json::Value = serde_json::from_slice(&numbers.stdout).unwrap();
    assert_eq!(numbers["runs"], 2, "{numbers}");
}
