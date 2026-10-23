//! The flow end to end through `devflow mcp`, as an agent CLI drives it: a
//! setup, the person's switch, a brief, a plan, an item started, its checks
//! run, its review, the gate and the finish — in a repository of its own,
//! with a home of its own.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Value};

struct Mcp {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    next: u64,
}

impl Mcp {
    fn start(repo: &Path, home: &Path) -> Mcp {
        let mut child = Command::new(env!("CARGO_BIN_EXE_devflow"))
            .arg("mcp")
            .current_dir(repo)
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env_remove("OPENROUTER_API_KEY")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Mcp {
            child,
            input,
            output,
            next: 1,
        }
    }

    fn ask(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        let line = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        writeln!(self.input, "{line}").unwrap();
        let mut answer = String::new();
        self.output.read_line(&mut answer).unwrap();
        serde_json::from_str(&answer).unwrap()
    }

    /// A tool's answer, which must not be an error.
    fn call(&mut self, name: &str, arguments: Value) -> Value {
        let said = self.ask(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        );
        let result = &said["result"];
        assert_eq!(
            result["isError"], false,
            "{name} failed: {}",
            result["content"][0]["text"]
        );
        result["structuredContent"].clone()
    }

    /// A tool's refusal, as text.
    fn refused(&mut self, name: &str, arguments: Value) -> String {
        let said = self.ask(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        );
        assert_eq!(said["result"]["isError"], true, "{name} did not refuse");
        said["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

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

/// A repository with one commit and a check that writes a JUnit report.
fn repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    git(root, &["init", "-q", "--initial-branch=main"]);
    git(root, &["config", "user.email", "test@example.invalid"]);
    git(root, &["config", "user.name", "Test"]);
    git(root, &["config", "commit.gpgsign", "false"]);
    std::fs::write(root.join("README.md"), "# shop\n").unwrap();
    std::fs::write(
        root.join("check.sh"),
        "#!/bin/sh\nmkdir -p \"$DEVFLOW_REPORT_DIR\"\ncat > \"$DEVFLOW_REPORT_DIR/report.xml\" <<'XML'\n<testsuite name=\"unit\" tests=\"1\" failures=\"0\"><testcase classname=\"rename\" name=\"renames_the_title\"/></testsuite>\nXML\n",
    )
    .unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "first"]);
    dir
}

#[cfg(unix)]
#[test]
fn an_item_goes_from_brief_to_done_on_its_evidence() {
    let repo = repo();
    let home = tempfile::tempdir().unwrap();
    let root = repo.path().canonicalize().unwrap();
    let mut mcp = Mcp::start(&root, home.path());
    mcp.ask("initialize", json!({ "protocolVersion": "2025-06-18" }));

    assert_eq!(mcp.call("status", json!({}))["state"], "no file");

    // The setup: previewed, then applied after the person's yes.
    let set = json!({
        "stages.execution.checks": [{ "name": "unit", "run": "sh check.sh", "report": "junit" }],
    });
    let preview = mcp.call("setup", json!({ "preset": "custom", "set": set }));
    assert_eq!(preview["applied"], false);
    let applied = mcp.call(
        "setup",
        json!({ "preset": "custom", "set": set, "apply": true }),
    );
    assert_eq!(applied["applied"], true, "{applied}");
    assert!(root.join(".devflow/devflow.yaml").is_file());
    assert!(root.join(".devflow/scripts/check-unit.sh").is_file());

    // Not on until the person switches it on, which no tool does.
    assert_eq!(mcp.call("status", json!({}))["state"], "disabled");
    let held = mcp.call(
        "set",
        json!({ "path": "enabled", "value": true, "apply": true }),
    );
    assert_eq!(held["asks"], json!(["enable"]), "{held}");
    assert!(std::fs::read_to_string(root.join(".devflow/devflow.yaml"))
        .unwrap()
        .contains("enabled: false"));
    assert!(mcp
        .refused("brief", json!({ "title": "Rename" }))
        .contains("not on"));
    let yaml = std::fs::read_to_string(root.join(".devflow/devflow.yaml")).unwrap();
    std::fs::write(
        root.join(".devflow/devflow.yaml"),
        yaml.replace("enabled: false", "enabled: true"),
    )
    .unwrap();
    std::fs::create_dir_all(home.path().join("config/devflow")).unwrap();
    std::fs::write(
        home.path().join("config/devflow/consent.json"),
        json!({ "enabled": [root.display().to_string()] }).to_string(),
    )
    .unwrap();
    assert_eq!(mcp.call("status", json!({}))["state"], "active");

    // Brief, plan previewed, plan applied after the yes.
    let epic = mcp.call(
        "brief",
        json!({ "title": "Rename a product", "goal": "Products can be renamed", "success": "the title changes", "out_of_scope": ["prices"] }),
    );
    let epic = epic["item"].as_str().unwrap().to_owned();
    let items = json!([{
        "key": "s1",
        "title": "Rename changes the title",
        "build": "A rename changes the product's title.",
        "criteria": ["rename changes the title"],
        "verify": "sh check.sh",
    }]);
    let shown = mcp.call("plan", json!({ "epic": epic, "items": items }));
    assert_eq!(shown["applied"], false);
    let made = mcp.call("plan", json!({ "epic": epic, "apply": true }));
    assert_eq!(made["applied"], true, "{made}");
    let item = made["starts_now"][0].as_str().unwrap().to_owned();
    assert_eq!(mcp.call("next", json!({ "epic": epic }))["item"], item);

    // The work: started, changed, its checks run with the criterion mapped.
    mcp.call("start", json!({ "item": item }));
    std::fs::write(root.join("src.txt"), "renamed\n").unwrap();
    git(&root, &["add", "src.txt"]);
    git(&root, &["commit", "-q", "-m", "rename"]);
    let evidence = mcp.call(
        "evidence",
        json!({
            "item": item,
            "criteria": [{ "criterion": "rename changes the title", "tests": ["rename.renames_the_title"] }],
        }),
    );
    assert!(evidence.to_string().contains("passed"), "{evidence}");

    // The gate holds it until the review is in.
    let held = mcp.call("gate", json!({ "item": item }));
    assert_eq!(held["result"], "failed", "{held}");
    assert!(mcp
        .refused("finish", json!({ "item": item }))
        .contains("stays"));

    // No reviewer CLI is set up: the session reviews each persona itself.
    let review = mcp.call("review", json!({ "item": item }));
    let run = review["run"].as_str().unwrap().to_owned();
    let pending: Vec<String> = review["pending"]
        .as_array()
        .unwrap()
        .iter()
        .map(|one| one.as_str().unwrap().to_owned())
        .collect();
    assert!(!pending.is_empty(), "{review}");
    let head = String::from_utf8(
        Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&root)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let reports: Vec<Value> = pending
        .iter()
        .map(|persona| {
            json!({
                "version": 1, "card": item, "base": review["base"], "head": head.trim(),
                "reviewers": [{ "agent": "session", "persona": persona }],
                "verdict": "approve",
                "findings": [],
                "done_well": ["a small change with its test"],
                "verification": { "tests": "read the report", "evidence": "the unit check is green" },
            })
        })
        .collect();
    let reviewed = mcp.call(
        "review",
        json!({ "item": item, "run": run, "reports": reports }),
    );
    assert!(
        reviewed["pending"].as_array().is_none_or(Vec::is_empty),
        "{reviewed}"
    );

    let gate = mcp.call("gate", json!({ "item": item }));
    assert_eq!(gate["result"], "passed", "{gate}");
    let finished = mcp.call("finish", json!({ "item": item, "note": "Renamed." }));
    assert_eq!(finished["state"], "done");
    assert_eq!(mcp.call("next", json!({ "epic": epic }))["next"], "done");

    let text = std::fs::read_to_string(root.join(format!(".devflow/work/{item}.md"))).unwrap();
    assert!(text.contains("state: done"), "{text}");
    assert!(text.contains("<!-- devflow:comments -->"), "{text}");
}
