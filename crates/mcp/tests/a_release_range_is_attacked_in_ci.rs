//! `devflow attack --range A..B`: a release range attacked headless, as CI
//! runs it. SARIF and JUnit are written, a hypothesis no sandbox ran is
//! warned of, and the month's budget holds for it as for any attack.

use std::path::Path;
use std::process::{Command, Output};

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
            "#!/bin/sh\ncat > /dev/null\ntouch '{}/asked'\ncat '{}/answer.json'\n",
            bin.display(),
            bin.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A project with two commits whose attack stage runs on releases, under
/// `month_usd`, and no exploit command: no sandbox is ever started.
fn project(month_usd: f64) -> (tempfile::TempDir, tempfile::TempDir) {
    let repo = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let root = repo.path();
    git(root, &["init", "-q", "--initial-branch=main"]);
    git(root, &["config", "user.email", "test@example.invalid"]);
    git(root, &["config", "user.name", "Test"]);
    git(root, &["config", "commit.gpgsign", "false"]);
    std::fs::create_dir_all(root.join(".devflow")).unwrap();
    std::fs::write(
        root.join(".devflow/devflow.yaml"),
        format!(
            "version: 2\nenabled: true\nstages:\n  - uses: builtin/execution\n    checks:\n      - {{ name: unit, run: \"true\", report: none }}\n  - uses: builtin/review\n    enabled: false\n  - uses: builtin/attack\n    run: release\n    budget: {{ month_usd: {month_usd} }}\n  - uses: builtin/completion\n"
        ),
    )
    .unwrap();
    std::fs::write(root.join(".gitignore"), ".devflow/runs/\n").unwrap();
    std::fs::write(root.join("README.md"), "# shop\n").unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "first"]);
    std::fs::create_dir_all(root.join("src/auth")).unwrap();
    std::fs::write(root.join("src/auth/session.rs"), "fn check() {}\n").unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "sessions"]);
    std::fs::create_dir_all(home.path().join("config/devflow")).unwrap();
    std::fs::write(
        home.path().join("config/devflow/consent.json"),
        json!({ "enabled": [root.canonicalize().unwrap().display().to_string()] }).to_string(),
    )
    .unwrap();
    (repo, home)
}

fn devflow(root: &Path, home: &Path, out: &Path, args: &[&str]) -> Output {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![home.join("bin")];
    paths.extend(std::env::split_paths(&path));
    Command::new(env!("CARGO_BIN_EXE_devflow"))
        .arg("--root")
        .arg(root)
        .args(args)
        .current_dir(out)
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("DEVFLOW_NO_UPDATE", "1")
        .env("GITHUB_ACTIONS", "true")
        .env_remove("OPENROUTER_API_KEY")
        .output()
        .unwrap()
}

#[cfg(unix)]
#[test]
fn a_release_range_is_attacked_headless_with_its_sarif_and_junit_written() {
    let (repo, home) = project(50.0);
    let root = repo.path().canonicalize().unwrap();
    fake_claude(
        &home.path().join("bin"),
        &json!({ "version": 1, "hypotheses": [
            { "id": "h1", "title": "a cookie signed with any key is accepted", "class": "authn",
              "file": "src/auth/session.rs", "line": 1, "severity": "high", "status": "tried",
              "reason": "the signature is never checked",
              "exploit": { "path": "tests/session.exploit.sh", "test": "forged-cookie", "code": "exit 1" } },
            { "id": "h2", "title": "the cookie is read over plain http", "class": "secrets",
              "file": "src/auth/session.rs", "line": 1, "severity": "low", "status": "refuted",
              "reason": "the server sets Secure" },
        ] }),
    );
    let out = tempfile::tempdir().unwrap();
    let ran = devflow(
        &root,
        home.path(),
        out.path(),
        &["attack", "--range", "HEAD~1..HEAD"],
    );
    let stderr = String::from_utf8_lossy(&ran.stderr);
    let stdout = String::from_utf8_lossy(&ran.stdout);
    assert!(ran.status.success(), "{stderr}");
    // Its exploit had no sandbox to run in: said loudly, never a quiet pass.
    assert!(
        stderr.contains("warning: devflow attack: h1 was not run, so it proves nothing either way"),
        "{stderr}"
    );
    assert!(
        stdout.contains("::warning title=devflow attack::h1 was not run"),
        "{stdout}"
    );
    let sarif: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(out.path().join("devflow-attack.sarif")).unwrap(),
    )
    .unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["results"], json!([]), "nothing confirmed");
    let junit = std::fs::read_to_string(out.path().join("devflow-attack.junit.xml")).unwrap();
    assert!(
        junit.contains("tests=\"2\" failures=\"0\" skipped=\"1\""),
        "{junit}"
    );
    assert!(
        junit.contains("name=\"h1 authn at src/auth/session.rs:1 (high)\"><skipped"),
        "{junit}"
    );
    assert!(
        !junit.contains("signature is never checked"),
        "the attack's words: {junit}"
    );
    // The paths the CI names are where they go.
    let named = devflow(
        &root,
        home.path(),
        out.path(),
        &[
            "attack",
            "--range",
            "HEAD~1...HEAD",
            "--sarif",
            "a.sarif",
            "--junit",
            "a.xml",
        ],
    );
    assert!(
        named.status.success(),
        "{}",
        String::from_utf8_lossy(&named.stderr)
    );
    assert!(out.path().join("a.sarif").is_file() && out.path().join("a.xml").is_file());
    // Not a range, or a range with an item, attacks nothing.
    for args in [
        &["attack", "--range", "HEAD"][..],
        &["attack", "card_1", "--range", "HEAD~1..HEAD"][..],
    ] {
        let refused = devflow(&root, home.path(), out.path(), args);
        assert!(!refused.status.success(), "{args:?}");
    }
}

#[cfg(unix)]
#[test]
fn a_release_range_past_the_months_budget_is_not_attacked() {
    let (repo, home) = project(1.0);
    let root = repo.path().canonicalize().unwrap();
    let bin = home.path().join("bin");
    fake_claude(&bin, &json!({ "version": 1, "hypotheses": [] }));
    let spent = json!({ "attackers": [{ "agent": "claude", "cost_usd": 2.0, "duration_ms": 1000 }], "hypotheses": [] });
    let run = devflow_engine::runs::stamp(std::time::SystemTime::now());
    devflow_engine::attack_metrics::record(&root.join(".devflow/runs"), "card_0", &run, &spent)
        .unwrap();
    let out = tempfile::tempdir().unwrap();
    let ran = devflow(
        &root,
        home.path(),
        out.path(),
        &["attack", "--range", "HEAD~1..HEAD"],
    );
    let stderr = String::from_utf8_lossy(&ran.stderr);
    assert_eq!(ran.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("month"), "{stderr}");
    assert!(!bin.join("asked").exists(), "no attacker was asked");
    assert!(!out.path().join("devflow-attack.sarif").exists());
}
