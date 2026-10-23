//! The context's tests, kept beside it.

use super::*;

fn sample() -> Context {
    Context {
        project: "shop".to_owned(),
        project_path: "/home/x/shop".to_owned(),
        worktree_path: "/home/x/shop".to_owned(),
        branch: "devflow/ship-it-01hzxy9k".to_owned(),
        base_ref: "9f1c2b7".to_owned(),
        item: "item_1".to_owned(),
        item_title: "Ship it".to_owned(),
        report_dir: "/home/x/shop/.devflow/runs/run_1".to_owned(),
        shared: Vec::new(),
        locks: Vec::new(),
    }
}

/// The preparation's shared variables reach the command, and none of them
/// can stand in for one of devflow's own.
#[test]
fn shared_variables_are_given_and_never_replace_devflows() {
    let context = Context {
        shared: vec![
            ("CARGO_TARGET_DIR".to_owned(), "/cache/target".to_owned()),
            ("DEVFLOW_ITEM".to_owned(), "item_forged".to_owned()),
        ],
        ..sample()
    };
    let env = context.environment();
    let value = |name: &str| {
        env.iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(value("CARGO_TARGET_DIR"), Some("/cache/target"));
    assert_eq!(value("DEVFLOW_ITEM"), Some("item_1"));
    assert_eq!(
        env.iter().filter(|(key, _)| key == "DEVFLOW_ITEM").count(),
        1
    );
}

#[test]
fn every_key_has_a_value_behind_it() {
    let context = sample();
    for key in CONTEXT_KEYS {
        assert!(context.get(key).is_some(), "no value for {key}");
    }
}

#[test]
fn a_key_that_does_not_exist_has_no_value() {
    assert_eq!(sample().get("secrets"), None);
}

#[test]
fn the_environment_names_are_what_a_shell_script_expects() {
    let environment = sample().environment();
    let names: Vec<&str> = environment.iter().map(|(k, _)| k.as_str()).collect();
    assert!(names.contains(&"DEVFLOW_PROJECT_PATH"));
    assert!(names.contains(&"DEVFLOW_ITEM_TITLE"));
    assert!(names.contains(&"DEVFLOW_BRANCH"));
    assert_eq!(names.len(), CONTEXT_KEYS.len() + LEGACY.len());
}

/// The whole reason the context travels this way.
#[test]
fn a_branch_name_full_of_shell_syntax_is_only_ever_a_value() {
    let context = Context {
        branch: "x; rm -rf /tmp/proof".to_owned(),
        ..sample()
    };
    let environment = context.environment();
    let (_, branch) = environment
        .iter()
        .find(|(k, _)| k == "DEVFLOW_BRANCH")
        .expect("no branch in the environment");
    assert_eq!(branch, "x; rm -rf /tmp/proof");
}

/// A check written for devpit's Devflow reads the names it always read.
#[test]
fn devpits_names_still_carry_the_same_values() {
    let environment = sample().environment();
    let value = |name: &str| {
        environment
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(value("DEVPIT_REPORT_DIR"), value("DEVFLOW_REPORT_DIR"));
    assert_eq!(value("DEVPIT_CARD"), Some("item_1"));
    assert_eq!(value("DEVPIT_CARD_TITLE"), Some("Ship it"));
}
