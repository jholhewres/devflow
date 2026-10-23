use super::*;
use crate::git::fixture;

fn git_in(dir: &Path, args: &[&str]) {
    let ok = crate::env::command("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .expect("git")
        .status
        .success();
    assert!(ok, "git {args:?}");
}

/// A team's layer: a repository with two tags, the second changing a skill.
fn team() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fixture::repo(dir.path());
    std::fs::create_dir_all(dir.path().join("skills/ticket")).expect("folder");
    std::fs::write(dir.path().join("devflow.yaml"), "version: 2\n").expect("yaml");
    std::fs::write(dir.path().join("skills/ticket/SKILL.md"), "first\n").expect("skill");
    fixture::commit(dir.path(), "one");
    git_in(dir.path(), &["tag", "v1"]);
    std::fs::write(dir.path().join("skills/ticket/SKILL.md"), "second\n").expect("skill");
    fixture::commit(dir.path(), "two");
    git_in(dir.path(), &["tag", "-a", "v2", "-m", "two"]);
    dir
}

#[test]
fn a_ref_is_fetched_to_its_commit_and_read_without_a_checkout() {
    let source = team();
    let home = tempfile::tempdir().expect("home");
    let cache = cache_for(home.path(), &source.path().display().to_string());
    let url = source.path().display().to_string();

    let first = fetch(&cache, &url, "v1").expect("v1");
    let second = fetch(&cache, &url, "v2").expect("v2 peels to its commit");
    assert_ne!(first, second);
    assert!(holds(&cache, &first), "an earlier commit stays readable");
    assert!(!cache.join("skills").exists(), "nothing is checked out");

    let listed = files(&cache, &first).expect("files");
    let paths: Vec<&str> = listed.iter().map(|one| one.path.as_str()).collect();
    assert!(paths.contains(&"skills/ticket/SKILL.md"), "{paths:?}");
    assert_eq!(
        read(&cache, &first, "skills/ticket/SKILL.md", MOST_FILE_BYTES).expect("read"),
        b"first\n"
    );
    assert_eq!(
        read(&cache, &second, "skills/ticket/SKILL.md", MOST_FILE_BYTES).expect("read"),
        b"second\n"
    );
    assert!(
        read(&cache, &first, "skills/ticket/SKILL.md", 2).is_err(),
        "past the cap"
    );
}

#[test]
fn a_ref_or_address_git_would_read_as_an_option_is_refused() {
    let home = tempfile::tempdir().expect("home");
    let cache = home.path().join("x.git");
    assert!(fetch(&cache, "--upload-pack=touch /tmp/x", "v1").is_err());
    assert!(fetch(&cache, "/somewhere", "--exec=x").is_err());
    assert!(read(&cache, "abc", "../outside", 10).is_err());
}
