use std::fs;
use std::process::Command;

fn devflow(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_devflow"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn the_help_names_the_flow_and_its_commands() {
    let out = devflow(&["--help"]);
    let said = String::from_utf8(out.stdout).unwrap();

    assert!(out.status.success());
    assert!(said.contains("evidence-gated"));
    assert!(said.contains("status"));
}

#[test]
fn a_project_without_a_configuration_exits_one() {
    let dir = tempfile::tempdir().unwrap();
    let out = devflow(&["status", "--root", dir.path().to_str().unwrap()]);

    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stdout)
        .unwrap()
        .starts_with("No configuration"));
}

#[test]
fn a_project_with_one_names_its_file() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("devflow.yaml"), "version: 2\n").unwrap();
    let out = devflow(&["status", "--root", dir.path().to_str().unwrap()]);

    assert!(out.status.success());
    assert!(String::from_utf8(out.stdout)
        .unwrap()
        .contains("devflow.yaml"));
}
