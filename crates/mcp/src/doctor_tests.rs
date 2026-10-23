use std::path::PathBuf;

use super::*;

fn machine(home: &Path) -> Machine {
    Machine {
        home: home.to_path_buf(),
        config: home.join(".config"),
        mac: false,
        has: Box::new(|_| false),
        ask: Box::new(|_| None),
    }
}

#[test]
fn a_project_without_devflow_is_told_how_to_set_it_up() {
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let consent = Consent::at(&home.path().join("devflow"));
    let said = findings(root.path(), &machine(home.path()), &consent, "/bin/devflow");
    assert!(said
        .iter()
        .any(|one| !one.ok && one.what.contains("no agent CLI or IDE found")));
    assert!(said
        .iter()
        .any(|one| one.optional && one.what.contains("`devflow setup`")));
}

#[test]
fn a_set_up_project_says_whether_it_is_on_and_its_runs_are_ignored() {
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let folder: PathBuf = root.path().join(".devflow");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("devflow.yaml"), "version: 2\nenabled: true\n").unwrap();
    let consent = Consent::at(&home.path().join("devflow"));
    let said = findings(root.path(), &machine(home.path()), &consent, "/bin/devflow");
    assert!(said
        .iter()
        .any(|one| !one.ok && one.what.contains("devflow is not on here")));
    assert!(said
        .iter()
        .any(|one| !one.ok && one.what.contains("does not ignore runs/")));
    consent.remember(root.path(), Ask::Enable, true).unwrap();
    std::fs::write(folder.join(".gitignore"), "runs/\n").unwrap();
    let said = findings(root.path(), &machine(home.path()), &consent, "/bin/devflow");
    assert!(said
        .iter()
        .any(|one| one.ok && one.what == "devflow is on here"));
    assert!(said
        .iter()
        .any(|one| one.ok && one.what.contains("kept out of git")));
}
