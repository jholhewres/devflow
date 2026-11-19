//! A project that writes its criteria under a heading of its own names it in
//! devflow.yaml's `criteria.headings`: the checkboxes under it then count in
//! the evidence and at the gate, as `## Acceptance criteria` does.

mod common;

use std::path::Path;
use std::process::Command;

use common::Mcp;

use serde_json::json;

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

#[cfg(unix)]
#[test]
fn criteria_under_a_heading_the_project_names_count() {
    let repo = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let root = repo.path().canonicalize().unwrap();
    git(&root, &["init", "-q", "--initial-branch=main"]);
    git(&root, &["config", "user.email", "test@example.invalid"]);
    git(&root, &["config", "user.name", "Test"]);
    git(&root, &["config", "commit.gpgsign", "false"]);
    std::fs::write(
        root.join("check.sh"),
        "#!/bin/sh\nmkdir -p \"$DEVFLOW_REPORT_DIR\"\ncat > \"$DEVFLOW_REPORT_DIR/report.xml\" <<'XML'\n<testsuite name=\"unit\" tests=\"1\" failures=\"0\"><testcase classname=\"rename\" name=\"renames_the_title\"/></testsuite>\nXML\n",
    )
    .unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "first"]);

    let mut mcp = Mcp::start(&root, home.path());
    mcp.ask("initialize", json!({ "protocolVersion": "2025-06-18" }));
    let set = json!({
        "stages.execution.checks": [{ "name": "unit", "run": "sh check.sh", "report": "junit" }],
        "criteria.headings": ["Critérios de aceite"],
    });
    mcp.call("setup", json!({ "preset": "custom", "set": set }));
    let applied = mcp.call(
        "setup",
        json!({ "preset": "custom", "set": set, "apply": true }),
    );
    assert_eq!(applied["applied"], true, "{applied}");
    let yaml = root.join(".devflow/devflow.yaml");
    let text = std::fs::read_to_string(&yaml).unwrap();
    std::fs::write(&yaml, text.replace("enabled: false", "enabled: true")).unwrap();
    std::fs::create_dir_all(home.path().join("config/devflow")).unwrap();
    std::fs::write(
        home.path().join("config/devflow/consent.json"),
        json!({ "enabled": [root.display().to_string()] }).to_string(),
    )
    .unwrap();
    assert_eq!(mcp.call("status", json!({}))["state"], "active");

    let made = mcp.call(
        "item",
        json!({
            "title": "Rename changes the title",
            "body": "## Critérios de aceite\n- [ ] rename changes the title\n",
        }),
    );
    let item = made["item"]
        .as_str()
        .or(made["id"].as_str())
        .unwrap()
        .to_owned();
    mcp.call("start", json!({ "item": item }));
    std::fs::write(root.join("src.txt"), "renamed\n").unwrap();
    git(&root, &["add", "src.txt"]);
    git(&root, &["commit", "-q", "-m", "rename"]);

    let evidence = mcp.call(
        "evidence",
        json!({
            "item": item,
            "criteria": [{
                "criterion": "rename changes the title",
                "tests": ["rename.renames_the_title"],
            }],
        }),
    );
    assert_eq!(evidence["criteria"][0]["on_card"], true, "{evidence}");
    assert_eq!(evidence["not_mapped"], json!([]), "{evidence}");
    assert!(evidence.get("criteria_unread").is_none(), "{evidence}");

    let gate = mcp.call("gate", json!({ "item": item }));
    // Held by the review alone: the criterion is read and has its evidence.
    assert_eq!(gate["criteria"], "1 of 1", "{gate}");
    assert_eq!(gate["missing"].as_array().unwrap().len(), 1, "{gate}");
    assert!(
        gate["missing"][0].as_str().unwrap().contains("no review"),
        "{gate}"
    );
}
