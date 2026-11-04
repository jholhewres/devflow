use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime};

use serde_json::{json, Value};

use super::*;

fn git(root: &Path, args: &[&str]) {
    let ran = Command::new("git")
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .current_dir(root)
        .output()
        .expect("git runs");
    assert!(
        ran.status.success(),
        "{}",
        String::from_utf8_lossy(&ran.stderr)
    );
}

fn repo() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("root");
    git(root.path(), &["init", "-q"]);
    std::fs::write(root.path().join("a.rs"), "fn a() {}\n").expect("a.rs");
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "-qm", "a"]);
    root
}

/// A run named a little before now, as evidence.json records it.
fn run_here(root: &Path) -> (String, Value) {
    let tree = tree_of(root).expect("a tree");
    let evidence = json!({
        "head": tree.head,
        "tree": tree.tracked,
        "criteria": [{ "criterion": "the dialog", "proof": { "kind": "screenshot", "path": "shots/dialog.png" } }],
    });
    (
        runs::stamp(SystemTime::now() - Duration::from_secs(5)),
        evidence,
    )
}

fn old(changed: Option<String>, run: &str) -> bool {
    changed.is_some_and(|changed| changed.as_str() > run)
}

#[test]
fn a_proof_written_after_the_run_leaves_it_fresh_and_new_code_does_not() {
    let root = repo();
    let (name, evidence) = run_here(root.path());
    std::fs::create_dir_all(root.path().join("shots")).expect("shots");
    std::fs::write(root.path().join("shots/dialog.png"), "png").expect("proof");
    std::fs::write(root.path().join(".devflow-note"), "x").expect("ours");
    let changed = changed_at(root.path(), Some((&name, &evidence)), &[".devflow"]);
    assert!(!old(changed.clone(), &name), "{changed:?}");

    std::fs::write(root.path().join("b.rs"), "fn b() {}\n").expect("an untracked source");
    assert!(old(
        changed_at(root.path(), Some((&name, &evidence)), &[]),
        &name
    ));
}

#[test]
fn a_tracked_edit_or_a_commit_after_the_run_makes_it_old_whatever_the_clocks_say() {
    let root = repo();
    let (_, evidence) = run_here(root.path());
    // A run stamped after every file was written: only the tree can tell.
    let name = runs::stamp(SystemTime::now() + Duration::from_secs(100));
    assert!(!old(
        changed_at(root.path(), Some((&name, &evidence)), &[]),
        &name
    ));

    std::fs::write(root.path().join("a.rs"), "fn a() { 1; }\n").expect("edit");
    assert!(old(
        changed_at(root.path(), Some((&name, &evidence)), &[]),
        &name
    ));

    git(root.path(), &["commit", "-qam", "edit"]);
    assert_eq!(
        git::dirty(root.path()).expect("status"),
        Vec::<String>::new()
    );
    assert!(old(
        changed_at(root.path(), Some((&name, &evidence)), &[]),
        &name
    ));
}

#[test]
fn a_run_that_recorded_no_tree_is_judged_by_when_files_were_written() {
    let root = repo();
    let now = SystemTime::now();
    let name = runs::stamp(now + Duration::from_secs(30));
    let before = json!({ "criteria": [{ "criterion": "the dialog", "proof": { "kind": "screenshot", "path": "shots/dialog.png" } }] });
    assert_eq!(changed_at(root.path(), Some((&name, &before)), &[]), None);
    std::fs::create_dir_all(root.path().join("shots")).expect("shots");
    let proof = root.path().join("shots/dialog.png");
    std::fs::write(&proof, "png").expect("proof");
    std::fs::File::options()
        .write(true)
        .open(&proof)
        .and_then(|file| file.set_modified(now + Duration::from_secs(60)))
        .expect("written after the run");
    // As in v0.2.1: any file written after the run, a proof too.
    assert!(old(
        changed_at(root.path(), Some((&name, &before)), &[]),
        &name
    ));
    assert_eq!(Tree::of(&before), None);
}

#[test]
fn outside_git_nothing_can_be_told() {
    let root = tempfile::tempdir().expect("root");
    assert_eq!(tree_of(root.path()), None);
    assert_eq!(changed_at(root.path(), None, &[]), None);
}
