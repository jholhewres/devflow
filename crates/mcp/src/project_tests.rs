use super::*;

#[test]
fn a_folder_inside_a_repository_stands_in_the_repository() {
    let repo = tempfile::tempdir().expect("repo");
    let ok = std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(repo.path())
        .status()
        .expect("git")
        .success();
    assert!(ok);
    std::fs::create_dir_all(repo.path().join("src/deep")).expect("folder");
    let project = Project::at(&repo.path().join("src/deep"));
    assert_eq!(project.root, repo.path().canonicalize().expect("root"));
    assert_eq!(project.dir(), ".devflow");
    assert_eq!(project.runs().home, project.root.join(".devflow/runs"));
}

#[test]
fn a_folder_outside_git_is_its_own_root() {
    let folder = tempfile::tempdir().expect("folder");
    let project = Project::at(folder.path());
    assert_eq!(project.root, folder.path().canonicalize().expect("root"));
}
