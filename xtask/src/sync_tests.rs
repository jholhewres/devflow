use std::fs;

use super::*;

const CARGO_TOML: &str = "[workspace.package]\nversion = \"0.0.1\"\n\n[workspace.dependencies]\ndevflow-engine = { path = \"crates/engine\", version = \"0.0.1\" }\n";

fn project(version: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::create_dir(root.join(".claude-plugin")).unwrap();
    fs::write(root.join("VERSION"), format!("{version}\n")).unwrap();
    fs::write(
        root.join(".claude-plugin/plugin.json"),
        r#"{"name":"devflow","version":"0.0.1"}"#,
    )
    .unwrap();
    fs::write(
        root.join(".claude-plugin/marketplace.json"),
        r#"{"metadata":{"version":"0.0.1"},"plugins":[{"name":"devflow","version":"0.0.1"}]}"#,
    )
    .unwrap();
    fs::write(
        root.join("gemini-extension.json"),
        r#"{"name":"devflow","version":"0.0.1"}"#,
    )
    .unwrap();
    fs::write(root.join("Cargo.toml"), CARGO_TOML).unwrap();
    dir
}

#[test]
fn manifests_that_agree_pass_with_their_tag() {
    let dir = project("0.0.1");
    assert_eq!(check(dir.path(), Some("v0.0.1")).unwrap(), "0.0.1");
}

#[test]
fn a_tag_that_is_not_the_version_fails() {
    let dir = project("0.0.1");
    let why = check(dir.path(), Some("v0.0.2")).unwrap_err();
    assert!(why.contains("tag v0.0.2"));
}

#[test]
fn every_field_behind_the_version_is_named() {
    let dir = project("0.0.2");
    let why = check(dir.path(), None).unwrap_err();
    for at in [
        "plugin.json /version",
        "marketplace.json /metadata/version",
        "marketplace.json /plugins/0/version",
        "gemini-extension.json /version",
        "[workspace.package] version",
        "[workspace.dependencies] devflow-engine",
    ] {
        assert!(why.contains(at), "{at} missing from: {why}");
    }
}

#[test]
fn a_sync_makes_the_check_pass() {
    let dir = project("0.1.0-rc.1");
    write(dir.path()).unwrap();
    assert_eq!(
        check(dir.path(), Some("v0.1.0-rc.1")).unwrap(),
        "0.1.0-rc.1"
    );
    let cargo = fs::read_to_string(dir.path().join("Cargo.toml")).unwrap();
    assert!(cargo.contains("path = \"crates/engine\", version = \"0.1.0-rc.1\" }"));
}
