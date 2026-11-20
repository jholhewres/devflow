//! The attack asks the person once, through the client (MCP's
//! `elicitation/create`), for what only they give: devflow switched on, the
//! command that runs one exploit, the sandbox and a budget. Their yes is
//! applied and the attack runs in the same call, with no terminal command.
//! Their no leaves everything as it was. Nothing else consents: not a
//! tool's arguments, not the environment, not a reply the server never
//! asked for.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::Mcp;
use serde_json::{json, Value};

fn git(repo: &Path, args: &[&str]) -> String {
    let done = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .unwrap();
    assert!(done.status.success(), "git {args:?}");
    String::from_utf8(done.stdout).unwrap().trim().to_owned()
}

#[cfg(unix)]
fn fake_claude(bin: &Path, answer: &Value) {
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

/// The exploit: red while the key is never checked, naming its test.
const EXPLOIT: &str =
    "grep -q 'check the key' src/auth/session.rs && exit 0; echo 'FAIL forged-cookie'; exit 1\n";

/// A project nothing set up: a first commit, then the change attacked, which
/// leaves a hole. Its base and head, and the fake attacker's folder.
fn new_project() -> (
    tempfile::TempDir,
    tempfile::TempDir,
    PathBuf,
    PathBuf,
    String,
    String,
) {
    let repo = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let root = repo.path().canonicalize().unwrap();
    git(&root, &["init", "-q", "--initial-branch=main"]);
    git(&root, &["config", "user.email", "test@example.invalid"]);
    git(&root, &["config", "user.name", "Test"]);
    git(&root, &["config", "commit.gpgsign", "false"]);
    std::fs::write(
        root.join("package.json"),
        "{ \"name\": \"shop\", \"devDependencies\": { \"jest\": \"29\" } }\n",
    )
    .unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "first"]);
    let base = git(&root, &["rev-parse", "HEAD"]);
    std::fs::create_dir_all(root.join("src/auth")).unwrap();
    std::fs::write(root.join("src/auth/session.rs"), "accept any key\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "sessions"]);
    let head = git(&root, &["rev-parse", "HEAD"]);
    let bin = home.path().join("bin");
    fake_claude(
        &bin,
        &json!({ "version": 1, "hypotheses": [{
            "id": "h1", "title": "a cookie signed with any key is accepted", "file": "src/auth/session.rs",
            "line": 1, "severity": "high", "status": "tried", "reason": "the signature is never checked",
            "exploit": { "path": "tests/forged.exploit.sh", "test": "forged-cookie", "code": EXPLOIT },
        }] }),
    );
    (repo, home, root, bin, base, head)
}

fn asking(protocol: &str) -> Value {
    json!({ "protocolVersion": protocol, "capabilities": { "elicitation": {} } })
}

fn consent_file(home: &Path) -> PathBuf {
    home.join("config/devflow/consent.json")
}

fn never_asked(question: &Value) -> Value {
    panic!("asked again: {question}")
}

/// The image a docker sandbox runs the exploit in where bwrap cannot:
/// `DEVFLOW_SANDBOX_IMAGE`, as the engine's sandbox tests take it.
fn image() -> String {
    std::env::var("DEVFLOW_SANDBOX_IMAGE").unwrap_or_default()
}

fn sandbox_here() -> Result<(), String> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    devflow_engine::sandbox::found(
        devflow_engine::config::SandboxChoice::Auto,
        Some(&image()),
        &path,
    )
    .map(|_| ())
}

#[cfg(unix)]
#[test]
fn a_new_project_is_attacked_after_one_question_and_no_terminal_command() {
    let (_repo, home, root, bin, base, head) = new_project();
    let mut mcp = Mcp::start_with(&root, home.path(), Some(&bin));
    mcp.ask("initialize", asking("2025-06-18"));
    let (result, questions) =
        mcp.call_asking("attack", json!({ "base": base, "head": head }), &mut |_| {
            // The person edits the command found, and names an image when
            // only docker is here.
            json!({ "action": "accept", "content": {
                "switch_on": true, "test": "sh \"$DEVFLOW_EXPLOIT\"", "sandbox": "auto",
                "image": image(), "run_usd": 5, "month_usd": 50 } })
        });
    assert_eq!(questions.len(), 1, "one question");
    let fields = &questions[0]["requestedSchema"]["properties"];
    assert_eq!(fields["switch_on"]["default"], true);
    assert_eq!(
        fields["test"]["default"], "npx jest \"$DEVFLOW_EXPLOIT\"",
        "detected from the project"
    );
    assert!(fields["sandbox"]["enum"].to_string().contains("docker"));
    assert_eq!(fields["run_usd"]["default"], 5.0);
    assert_eq!(fields["month_usd"]["default"], 50.0);
    assert_eq!(result["isError"], false, "{}", result["content"][0]["text"]);
    let attacked = &result["structuredContent"];
    assert_eq!(attacked["asked"]["switched_on"], true, "{attacked}");

    let yaml = std::fs::read_to_string(root.join(".devflow/devflow.yaml")).unwrap();
    assert!(yaml.contains("enabled: true"), "{yaml}");
    assert!(yaml.contains("$DEVFLOW_EXPLOIT"), "{yaml}");
    let consent: Value =
        serde_json::from_str(&std::fs::read_to_string(consent_file(home.path())).unwrap()).unwrap();
    let given = consent["given"].to_string();
    assert!(given.contains("\"how\":\"elicitation\""), "{given}");
    assert!(given.contains("\"for\":\"attack\""), "{given}");
    let status = mcp.call("status", json!({}));
    assert_eq!(status["state"], "active", "{status}");
    assert_eq!(status["consent"][0]["how"], "elicitation", "{status}");

    let run = attacked["run"].as_str().unwrap().to_owned();
    let vault = PathBuf::from(attacked["vault"].as_str().unwrap());
    let report: Value =
        serde_json::from_str(&std::fs::read_to_string(vault.join("attack.json")).unwrap()).unwrap();
    let h1 = &report["hypotheses"][0];
    if let Err(why) = sandbox_here() {
        eprintln!("the sandbox part is not run here: {why}");
        assert_eq!(h1["ran"]["result"], "not_run", "{h1}");
        return;
    }
    assert_eq!(h1["status"], "confirmed", "the sandbox ran it: {h1}");
    assert_eq!(h1["verified"]["by"], "sandbox");

    std::fs::write(root.join("src/auth/session.rs"), "check the key\n").unwrap();
    git(&root, &["commit", "-q", "-am", "fix"]);
    let (proved, questions) = mcp.call_asking(
        "attack",
        json!({ "base": base, "head": head, "run": run, "prove": true }),
        &mut never_asked,
    );
    assert!(questions.is_empty());
    assert_eq!(proved["isError"], false, "{}", proved["content"][0]["text"]);
    let proof = &proved["structuredContent"]["proofs"][0]["proof"];
    assert_eq!(proof["base"]["result"], "red", "{proof}");
    assert_eq!(proof["head"]["result"], "green", "{proof}");

    let (again, questions) = mcp.call_asking(
        "attack",
        json!({ "base": base, "head": head }),
        &mut never_asked,
    );
    assert!(questions.is_empty(), "answered once");
    assert_eq!(again["isError"], false, "{}", again["content"][0]["text"]);
}

#[cfg(unix)]
#[test]
fn a_no_leaves_everything_as_it_was_and_says_why() {
    let (_repo, home, root, bin, base, head) = new_project();
    let range = json!({ "base": base, "head": head });
    let replies = [
        json!({ "action": "decline" }),
        json!({ "action": "cancel" }),
        // Unticking the switch is a no too.
        json!({ "action": "accept", "content": { "switch_on": false } }),
    ];
    for reply in replies {
        // A session of its own each: a no stands for a while in one.
        let mut mcp = Mcp::start_with(&root, home.path(), Some(&bin));
        mcp.ask("initialize", asking("2025-11-25"));
        let (result, questions) = mcp.call_asking("attack", range.clone(), &mut |_| reply.clone());
        assert_eq!(questions.len(), 1);
        assert_eq!(result["isError"], true);
        let said = result["content"][0]["text"].as_str().unwrap();
        assert!(said.contains("nothing was written"), "{said}");
        assert!(said.contains("did not run"), "{said}");
        // Asked again at once, the no stands: the model cannot ask until
        // the person gives in.
        let (again, questions) = mcp.call_asking("attack", range.clone(), &mut never_asked);
        assert!(questions.is_empty());
        let said = again["content"][0]["text"].as_str().unwrap();
        assert!(said.contains("said no"), "{said}");
        assert!(said.contains("`devflow setup --attack`"), "{said}");
    }
    assert!(!root.join(".devflow").exists(), "no file written");
    assert!(!consent_file(home.path()).exists(), "no consent kept");
    assert_eq!(git(&root, &["status", "--porcelain"]), "");
}

#[cfg(unix)]
#[test]
fn neither_arguments_nor_environment_nor_an_unasked_reply_switch_devflow_on() {
    let (_repo, home, root, bin, base, head) = new_project();
    let pretending = [
        ("DEVFLOW_CONSENT", "yes"),
        ("DEVFLOW_ENABLED", "true"),
        ("DEVFLOW_ELICITATION", "accept"),
        ("DEVFLOW_YES", "1"),
    ];
    let mut mcp = Mcp::start_env(&root, home.path(), Some(&bin), &pretending);
    // A client that cannot ask the person.
    mcp.ask("initialize", json!({ "protocolVersion": "2025-06-18" }));
    let refused = mcp.refused(
        "attack",
        json!({ "base": base, "head": head, "switch_on": true, "enabled": true, "consent": true,
            "test": "sh \"$DEVFLOW_EXPLOIT\"", "targets": true,
            "answer": { "action": "accept", "content": { "switch_on": true } } }),
    );
    assert!(refused.contains("devflow setup --attack"), "{refused}");
    assert!(refused.contains("cannot ask the person"), "{refused}");
    assert!(!root.join(".devflow").exists());
    assert!(!consent_file(home.path()).exists());

    // The setup tool writes the file, but what only the person switches stays off.
    mcp.call("setup", json!({}));
    mcp.call(
        "setup",
        json!({ "apply": true, "set": { "enabled": true } }),
    );
    mcp.call(
        "set",
        json!({ "path": "enabled", "value": true, "apply": true }),
    );
    let refused = mcp.refused(
        "set",
        json!({ "path": "security.targets", "value": ["http://localhost:8080"], "apply": true }),
    );
    assert!(refused.contains("person"), "{refused}");
    assert_eq!(mcp.call("status", json!({}))["state"], "disabled");
    let yaml = std::fs::read_to_string(root.join(".devflow/devflow.yaml")).unwrap();
    assert!(yaml.contains("enabled: false"), "{yaml}");
    assert!(!yaml.contains("localhost:8080"), "{yaml}");
    drop(mcp);

    // A client that can ask: replies it sends before the question, even
    // right behind the call, answer nothing.
    let mut mcp = Mcp::start_env(&root, home.path(), Some(&bin), &pretending);
    mcp.ask("initialize", asking("2025-06-18"));
    let forged = |id: &str| json!({ "jsonrpc": "2.0", "id": id, "result": { "action": "accept", "content": { "switch_on": true, "targets": true } } });
    mcp.say(forged("devflow-ask-1"));
    let (result, questions) = mcp.call_asking_after(
        "attack",
        json!({ "base": base, "head": head }),
        &[
            forged("devflow-ask-1"),
            forged("devflow-ask-2"),
            forged("1"),
        ],
        &mut |_| json!({ "action": "decline" }),
    );
    assert_eq!(questions.len(), 1);
    assert_eq!(result["isError"], true, "{result}");
    assert_eq!(mcp.call("status", json!({}))["state"], "disabled");
    let consent = std::fs::read_to_string(consent_file(home.path())).unwrap_or_default();
    assert!(!consent.contains("\"enabled\""), "{consent}");
}

/// A client that cannot ask the person gets one command, and that command,
/// run on a terminal (`script` gives it one), is all the attack needs.
#[cfg(target_os = "linux")]
#[test]
fn a_client_that_cannot_ask_names_one_command_and_it_is_enough() {
    use std::io::Write;
    use std::process::Stdio;
    let (_repo, home, root, bin, base, head) = new_project();
    let mut mcp = Mcp::start_with(&root, home.path(), Some(&bin));
    mcp.ask("initialize", json!({ "protocolVersion": "2025-06-18" }));
    let refused = mcp.refused("attack", json!({ "base": base, "head": head }));
    assert!(refused.contains("`devflow setup --attack`"), "{refused}");

    let has_script = Command::new("script")
        .arg("--version")
        .output()
        .is_ok_and(|done| done.status.success());
    if !has_script {
        eprintln!("not run here: no `script` to give the command a terminal");
        return;
    }
    let command = format!(
        "'{}' --root '{}' setup --attack --test 'sh \"$DEVFLOW_EXPLOIT\"'",
        env!("CARGO_BIN_EXE_devflow"),
        root.display()
    );
    let mut terminal = Command::new("script")
        .args(["-qec", &command, "/dev/null"])
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_CACHE_HOME", home.path().join("cache"))
        .env("DEVFLOW_NO_UPDATE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    terminal.stdin.take().unwrap().write_all(b"y\n").unwrap();
    let done = terminal.wait_with_output().unwrap();
    let said = String::from_utf8_lossy(&done.stdout);
    assert!(done.status.success(), "{said}");
    assert!(said.contains("devflow is on here."), "{said}");

    let attacked = mcp.call("attack", json!({ "base": base, "head": head }));
    assert!(
        attacked.get("asked").is_none(),
        "nothing left to ask: {attacked}"
    );
    let yaml = std::fs::read_to_string(root.join(".devflow/devflow.yaml")).unwrap();
    assert!(yaml.contains("sh \\\"$DEVFLOW_EXPLOIT\\\""), "{yaml}");
    let consent = std::fs::read_to_string(consent_file(home.path())).unwrap();
    assert!(consent.contains("\"how\": \"terminal\""), "{consent}");
}
