use serde_json::json;

use super::*;
use crate::config::Mode;
use crate::preset::{changes, with_set};

const HAND_WRITTEN: &str = "\
# Our flow. Ask Ana before changing the gate.
version: 1
enabled: false   # flipped by the app
stages:
  plan: { approve: person }
decisions:
  mode: shadow # for now
";

fn project(text: Option<&str>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    if let Some(text) = text {
        std::fs::create_dir_all(dir.path().join(DIR)).expect("folder");
        std::fs::write(dir.path().join(FILE), text).expect("write");
    }
    dir
}

#[test]
fn a_project_without_the_file_has_none() {
    assert_eq!(read(project(None).path()), State::Missing);
}

#[test]
fn an_invalid_file_keeps_its_text_and_the_reason() {
    let dir = project(Some("version: 1\nenabled: maybe\n"));
    let State::Invalid(Some(text), invalid) = read(dir.path()) else {
        panic!("invalid");
    };
    assert!(text.contains("maybe"));
    assert_eq!((invalid.line, invalid.field.as_str()), (Some(2), "enabled"));
}

#[test]
fn a_file_too_large_to_be_a_setting_is_not_read() {
    let big = format!("version: 1\n# {}\n", "x".repeat(MOST_BYTES as usize));
    assert!(matches!(
        read(project(Some(&big)).path()),
        State::Invalid(None, _)
    ));
}

#[cfg(unix)]
#[test]
fn a_file_that_leads_outside_the_project_is_refused() {
    let outside = project(Some("version: 1\n"));
    let dir = project(None);
    std::fs::create_dir_all(dir.path().join(DIR)).expect("folder");
    std::os::unix::fs::symlink(outside.path().join(FILE), dir.path().join(FILE)).expect("link");
    assert!(matches!(read(dir.path()), State::Invalid(None, _)));
}

#[test]
fn a_word_changed_keeps_the_persons_comments_and_layout() {
    let before = crate::config::parse(HAND_WRITTEN).expect("valid");
    let mut after = before.clone();
    after.enabled = true;
    after.decisions.mode = Mode::Enforce;
    let (text, laid_out) = rewritten(Some(HAND_WRITTEN), &changes(Some(&before), &after), &after);
    assert!(!laid_out);
    assert_eq!(
        text,
        HAND_WRITTEN
            .replace("enabled: false   #", "enabled: true   #")
            .replace("mode: shadow #", "mode: enforce #")
    );
}

#[test]
fn a_change_larger_than_a_word_lays_the_file_out_again() {
    let before = crate::config::parse(HAND_WRITTEN).expect("valid");
    let after = with_set(&before, "review.block_on", &json!(["critical"])).expect("set");
    let (text, laid_out) = rewritten(Some(HAND_WRITTEN), &changes(Some(&before), &after), &after);
    assert!(laid_out);
    assert_eq!(crate::config::parse(&text), Ok(after));
}

/// A project on devpit's Devflow keeps its folder, its file and its specs
/// where they are; a new one gets `.devflow/`, and `devflow.yaml` at the root
/// keeps the folder `.devflow/`.
#[test]
fn a_project_is_read_where_it_keeps_devflow() {
    let legacy = tempfile::tempdir().expect("legacy");
    std::fs::create_dir_all(legacy.path().join(LEGACY)).expect("folder");
    std::fs::write(
        legacy.path().join(crate::locate::DEVPIT),
        "version: 2\nenabled: true\n",
    )
    .expect("write");
    assert_eq!(dir(legacy.path()), LEGACY);
    assert_eq!(file(legacy.path()), ".devpit/devflow/devflow.yaml");
    let State::Valid(_, config) = read(legacy.path()) else {
        panic!("devflow's file is read");
    };
    assert_eq!(
        config.stages.execution.e2e_dir,
        crate::config::LEGACY_E2E_DIR
    );

    let fresh = tempfile::tempdir().expect("fresh");
    assert_eq!(Layout::of(fresh.path()), Layout::default());
    assert_eq!(read(fresh.path()), State::Missing);

    let at_root = tempfile::tempdir().expect("root");
    std::fs::write(at_root.path().join("devflow.yaml"), "version: 2\n").expect("write");
    assert_eq!(dir(at_root.path()), DIR);
    assert_eq!(file(at_root.path()), "devflow.yaml");
    let State::Valid(_, config) = read(at_root.path()) else {
        panic!("the root's file is read");
    };
    assert_eq!(config.stages.execution.e2e_dir, crate::config::E2E_DIR);

    // Once `.devflow/` has a configuration it is the one that applies.
    std::fs::create_dir_all(legacy.path().join(DIR)).expect("folder");
    std::fs::write(legacy.path().join(FILE), "version: 2\n").expect("write");
    assert_eq!(Layout::of(legacy.path()), Layout::default());
}
