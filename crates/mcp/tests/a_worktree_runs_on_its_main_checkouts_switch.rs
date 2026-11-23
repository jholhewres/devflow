//! A linked worktree of a repository whose main checkout has devflow on
//! takes that switch and that consent, and its devflow folder by a symlink
//! to the main checkout's: kept out of git, a worktree has none of its own.
//! Two worktrees run the attack, a review and the gate with no question.

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
fn fake_claude(bin: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(bin).unwrap();
    let answer = json!({ "version": 1, "hypotheses": [] });
    let envelope = json!({ "type": "result", "result": answer.to_string(), "total_cost_usd": 0.1 });
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

fn never_asked(question: &Value) -> Value {
    panic!("asked in a worktree: {question}")
}

#[cfg(unix)]
#[test]
fn two_worktrees_run_on_the_main_checkouts_switch_with_no_question() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let base_dir = dir.path().canonicalize().unwrap();
    let main = base_dir.join("main");
    std::fs::create_dir_all(main.join("src/auth")).unwrap();
    git(&main, &["init", "-q", "--initial-branch=main"]);
    git(&main, &["config", "user.email", "test@example.invalid"]);
    git(&main, &["config", "user.name", "Test"]);
    git(&main, &["config", "commit.gpgsign", "false"]);
    // devpit's folder is kept out of git, as devpit sets it up.
    std::fs::write(main.join(".gitignore"), ".devpit/\n").unwrap();
    std::fs::write(main.join("src/auth/session.rs"), "fn a() {}\n").unwrap();
    git(&main, &["add", "-A"]);
    git(&main, &["commit", "-q", "-m", "first"]);
    let base = git(&main, &["rev-parse", "HEAD"]);
    std::fs::write(
        main.join("src/auth/session.rs"),
        "fn a() {}\nfn decode() {}\n",
    )
    .unwrap();
    git(&main, &["commit", "-q", "-am", "decode"]);
    let head = git(&main, &["rev-parse", "HEAD"]);
    std::fs::create_dir_all(main.join(".devpit/devflow")).unwrap();
    std::fs::write(
        main.join(".devpit/devflow/devflow.yaml"),
        "version: 2\nenabled: true\nstages:\n  attack:\n    run: release\n    test: 'sh \"$DEVFLOW_EXPLOIT\"'\n    image: 'node:22'\n    sandbox: off\n",
    )
    .unwrap();
    // The person switched devflow on in the main checkout only.
    std::fs::create_dir_all(home.path().join("config/devflow")).unwrap();
    std::fs::write(
        home.path().join("config/devflow/consent.json"),
        json!({ "enabled": [main.display().to_string()] }).to_string(),
    )
    .unwrap();
    let bin = base_dir.join("bin");
    fake_claude(&bin);

    // Two worktrees: one links devpit's folder whole, the other its devflow
    // folder inside a folder of its own.
    let one = base_dir.join("wt1");
    let two = base_dir.join("wt2");
    git(
        &main,
        &["worktree", "add", "-q", one.to_str().unwrap(), "-b", "wt1"],
    );
    git(
        &main,
        &["worktree", "add", "-q", two.to_str().unwrap(), "-b", "wt2"],
    );
    std::os::unix::fs::symlink(main.join(".devpit"), one.join(".devpit")).unwrap();
    std::fs::create_dir_all(two.join(".devpit")).unwrap();
    std::os::unix::fs::symlink(main.join(".devpit/devflow"), two.join(".devpit/devflow")).unwrap();

    for worktree in [&one, &two] {
        let mut mcp = Mcp::start_with(worktree, home.path(), Some(&bin));
        mcp.ask(
            "initialize",
            json!({ "protocolVersion": "2025-06-18", "capabilities": { "elicitation": {} } }),
        );
        let status = mcp.call("status", json!({}));
        assert_eq!(
            status["state"],
            "active",
            "{}: {status}",
            worktree.display()
        );

        let (attacked, questions) = mcp.call_asking(
            "attack",
            json!({ "base": base, "head": head }),
            &mut never_asked,
        );
        assert!(questions.is_empty());
        assert_eq!(
            attacked["isError"], false,
            "{}",
            attacked["content"][0]["text"]
        );

        let (reviewed, questions) = mcp.call_asking(
            "review",
            json!({ "base": base, "head": head }),
            &mut never_asked,
        );
        assert!(questions.is_empty());
        assert_eq!(
            reviewed["isError"], false,
            "{}",
            reviewed["content"][0]["text"]
        );

        let epic = mcp.call(
            "brief",
            json!({ "title": "Decode", "goal": "Cookies decode", "success": "a cookie decodes", "out_of_scope": [] }),
        );
        let item = epic["item"].as_str().expect("an item").to_owned();
        let (gated, questions) = mcp.call_asking("gate", json!({ "item": item }), &mut never_asked);
        assert!(questions.is_empty());
        assert_eq!(gated["isError"], false, "{}", gated["content"][0]["text"]);
        assert!(
            gated["structuredContent"]["result"].is_string(),
            "{}",
            gated["structuredContent"]
        );
    }
    // The items each worktree made are in the main checkout's folder.
    let work: Vec<PathBuf> = std::fs::read_dir(main.join(".devpit/devflow/work"))
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .collect();
    assert_eq!(work.len(), 2, "{work:?}");

    // The doctor says where the switch comes from.
    let doctor = Command::new(env!("CARGO_BIN_EXE_devflow"))
        .arg("doctor")
        .current_dir(&one)
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_CACHE_HOME", home.path().join("cache"))
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&doctor.stdout);
    assert!(
        said.contains(&format!(
            "this worktree takes the switch of its repository's main checkout, {}",
            main.display()
        )),
        "{said}"
    );
}

/// A worktree's devflow folder that leads anywhere but the same folder of
/// its own repository's main checkout is still refused.
#[cfg(unix)]
#[test]
fn a_worktrees_devflow_folder_linked_elsewhere_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let main = root.join("main");
    let other = root.join("other");
    for repo in [&main, &other] {
        std::fs::create_dir_all(repo.join(".devpit/devflow")).unwrap();
        git(repo, &["init", "-q", "--initial-branch=main"]);
        git(repo, &["config", "user.email", "test@example.invalid"]);
        git(repo, &["config", "user.name", "Test"]);
        git(repo, &["config", "commit.gpgsign", "false"]);
        std::fs::write(repo.join(".gitignore"), ".devpit/\n").unwrap();
        git(repo, &["add", "-A"]);
        git(repo, &["commit", "-q", "-m", "first"]);
        std::fs::write(
            repo.join(".devpit/devflow/devflow.yaml"),
            "version: 2\nenabled: true\n",
        )
        .unwrap();
    }
    let worktree = root.join("wt");
    git(
        &main,
        &[
            "worktree",
            "add",
            "-q",
            worktree.to_str().unwrap(),
            "-b",
            "wt",
        ],
    );
    // Another repository's folder.
    std::os::unix::fs::symlink(other.join(".devpit"), worktree.join(".devpit")).unwrap();
    let mut mcp = Mcp::start(&worktree, home.path());
    mcp.ask("initialize", json!({ "protocolVersion": "2025-06-18" }));
    let status = mcp.call("status", json!({}));
    assert_eq!(status["state"], "invalid", "{status}");
    // The main checkout's, but another of its folders.
    std::fs::remove_file(worktree.join(".devpit")).unwrap();
    std::fs::create_dir_all(main.join("elsewhere/devflow")).unwrap();
    std::fs::write(
        main.join("elsewhere/devflow/devflow.yaml"),
        "version: 2\nenabled: true\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(main.join("elsewhere"), worktree.join(".devpit")).unwrap();
    let status = mcp.call("status", json!({}));
    assert_eq!(status["state"], "invalid", "{status}");
}
