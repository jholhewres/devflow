use super::*;
use crate::git::fixture;

fn repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fixture::repo(dir.path());
    std::fs::write(dir.path().join("a.rs"), "one\n").expect("write");
    fixture::commit(dir.path(), "first");
    dir
}

#[test]
fn a_review_reads_the_commits_and_then_what_is_not_committed() {
    let dir = repo();
    let base = head_of(dir.path()).expect("head");
    std::fs::write(dir.path().join("b.rs"), "two\n").expect("write");
    fixture::commit(dir.path(), "second");
    std::fs::write(dir.path().join("a.rs"), "one\nmore\n").expect("write");
    let head = head_of(dir.path()).expect("head");
    let read = review_diff(dir.path(), &base, &head).expect("diff");
    assert_eq!(read.files, ["b.rs", "a.rs"]);
    assert_eq!(read.commits, 1);
    assert!(read.diff.contains(UNCOMMITTED));
    assert_eq!(review_base(dir.path(), None).expect("base"), head);
    assert_eq!(
        changed_since(dir.path(), &base).expect("changed"),
        ["a.rs", "b.rs"]
    );
    assert_eq!(dirty(dir.path()).expect("dirty"), ["a.rs"]);
    assert_eq!(
        lines_at(dir.path(), &head, "a.rs", 1024).expect("lines"),
        Some(1)
    );
    assert_eq!(
        lines_at(dir.path(), &head, "gone.rs", 1024).expect("lines"),
        None
    );
}

#[test]
fn what_devflow_writes_is_not_a_change_to_the_code() {
    let dir = repo();
    let from = head_of(dir.path()).expect("head");
    std::fs::create_dir_all(dir.path().join(".devflow/work")).expect("folder");
    std::fs::write(
        dir.path().join(".devflow/work/1.md"),
        "---\ntitle: x\n---\n",
    )
    .expect("write");
    fixture::commit(dir.path(), "an item");
    let to = head_of(dir.path()).expect("head");
    assert!(!code_changed_between(dir.path(), &from, &to).expect("diff"));
}

#[test]
fn a_revision_that_reads_as_an_option_is_refused_before_git_is_asked() {
    let dir = repo();
    assert!(matches!(
        review_base(dir.path(), Some("--output=/tmp/x")),
        Err(GitError::Refused(_))
    ));
    assert!(matches!(
        commit_of(dir.path(), "-x"),
        Err(GitError::Refused(_))
    ));
    assert!(lines_at(dir.path(), "HEAD", "../etc/passwd", 10).is_err());
}

#[test]
fn a_detached_worktree_comes_and_goes_without_moving_the_checkout() {
    let dir = repo();
    let head = head_of(dir.path()).expect("head");
    let at = dir.path().join(".devflow/runs/review-tree");
    add_detached(dir.path(), &at, &head).expect("added");
    assert!(at.join("a.rs").is_file());
    assert_eq!(branch_at(dir.path()).expect("branch"), "main");
    remove_detached(dir.path(), &at);
    assert!(!at.exists());
    assert_eq!(branches(dir.path()).expect("branches"), ["main"]);
    assert_eq!(subjects(dir.path(), 5), ["first"]);
}
