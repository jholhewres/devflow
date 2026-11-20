//! A retro review held to the security axis over MCP: only security waits on
//! the session, its exploits are written to the run's vault outside the
//! checkout, and its report says each finding confirmed, not confirmed or
//! not run, with where its exploit is.

mod common;

use std::path::Path;
use std::process::Command;

use common::Mcp;
use serde_json::{json, Value};

fn git(repo: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .args(args)
        .current_dir(repo)
        .status()
        .unwrap()
        .success();
    assert!(ok, "git {args:?}");
}

#[test]
fn a_security_retro_waits_only_on_security_and_reports_from_its_vault() {
    let repo = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let root = repo.path().canonicalize().unwrap();
    git(&root, &["init", "-q", "--initial-branch=main"]);
    git(&root, &["config", "user.email", "test@example.invalid"]);
    git(&root, &["config", "user.name", "Test"]);
    git(&root, &["config", "commit.gpgsign", "false"]);
    std::fs::write(root.join("README.md"), "# shop\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "first"]);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("src/open.py"),
        "os.system(f\"xdg-open {link}\")\n",
    )
    .unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "open links"]);
    let mut mcp = Mcp::start(&root, home.path());
    mcp.ask("initialize", json!({ "protocolVersion": "2025-06-18" }));
    let range = json!({ "base": "HEAD~1", "head": "HEAD", "mode": "retro" });
    let mut asked = range.clone();
    asked["axes"] = json!(["security"]);
    let first = mcp.call("review", asked);
    let pending: Vec<&str> = first["pending"]
        .as_array()
        .unwrap_or_else(|| panic!("{first}"))
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        pending,
        ["devflow-security"],
        "only security waits: {first}"
    );
    let run = first["run"].as_str().unwrap().to_owned();
    let label = first["reviewed"].as_str().unwrap().to_owned();
    let head = String::from_utf8(
        Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&root)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let report = json!({
        "version": 1, "card": label, "base": first["base"], "head": head.trim(),
        "reviewers": [{ "agent": "session", "persona": "devflow-security" }],
        "verdict": "request_changes",
        "findings": [{
            "file": "src/open.py", "line": 1, "severity": "high", "axis": "security",
            "title": "Shell injection in open", "description": "a link reaches a shell",
            "evidence": "os.system(f\"xdg-open {link}\")", "agent": "session", "persona": "devflow-security",
            "impact": "grep -c 'xdg-open' in the app's logs since the deploy",
            "poc": "open the link 'x;true' and see the shell run it",
        }],
        "done_well": ["a one-line change"],
        "verification": { "tests": "read the diff", "evidence": "one line" },
    });
    let mut handed = range.clone();
    handed["run"] = json!(run);
    handed["reports"] = json!([report]);
    let second = mcp.call("review", handed);
    assert!(
        second["pending"].as_array().is_none_or(Vec::is_empty),
        "{second}"
    );
    let vault = second["vault"]
        .as_str()
        .unwrap_or_else(|| panic!("{second}"))
        .to_owned();
    assert!(
        !Path::new(&vault).starts_with(&root),
        "the vault is outside the checkout: {vault}"
    );
    assert!(
        second["next"].as_str().unwrap().contains(&vault),
        "{second}"
    );
    assert_eq!(second["report"][0]["status"], "not run", "{second}");

    let exploit = format!("{vault}/f0/open_exploit.sh");
    let mut proved = range.clone();
    proved["run"] = json!(run);
    proved["verified"] = json!([{ "finding": 0, "result": "confirmed", "evidence": "red in the vault", "test": exploit }]);
    let third = mcp.call("review", proved);
    assert_eq!(third["report"][0]["status"], "confirmed", "{third}");
    assert_eq!(third["report"][0]["exploit"], exploit.as_str());
    let folder = third["folder"]
        .as_str()
        .unwrap_or_else(|| panic!("{third}"));
    let markdown = std::fs::read_to_string(Path::new(folder).join("retro-report.md")).unwrap();
    assert!(markdown.contains(&format!("[confirmed] high src/open.py:1 Shell injection in open (finding 0); exploit: {exploit}")), "{markdown}");
    assert!(!root.join("f0").exists() && !root.join("exploits").exists());
}
