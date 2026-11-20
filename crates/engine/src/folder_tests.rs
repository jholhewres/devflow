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
fn a_change_larger_than_a_word_keeps_the_persons_comments_too() {
    let before = crate::config::parse(HAND_WRITTEN).expect("valid");
    let after = with_set(&before, "review.block_on", &json!(["critical"])).expect("set");
    let (text, laid_out) = rewritten(Some(HAND_WRITTEN), &changes(Some(&before), &after), &after);
    assert!(!laid_out, "{text}");
    assert!(text.starts_with(HAND_WRITTEN), "{text}");
    assert_eq!(crate::config::parse(&text), Ok(after));
}

#[test]
fn a_file_that_cannot_be_edited_in_place_is_laid_out_again() {
    let flow = "version: 1
enabled: false
review: { consolidate: none }
";
    let before = crate::config::parse(flow).expect("valid");
    let after = with_set(&before, "review.block_on", &json!(["critical"])).expect("set");
    let (text, laid_out) = rewritten(Some(flow), &changes(Some(&before), &after), &after);
    assert!(laid_out, "{text}");
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

#[test]
fn a_project_on_devpits_folder_is_compared_as_it_is_read() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::create_dir_all(dir.path().join(LEGACY)).expect("folder");
    let text = "version: 1\nreview:\n  consolidate: jev # ours\n";
    std::fs::write(dir.path().join(crate::locate::DEVPIT), text).expect("write");
    let State::Valid(_, before) = read(dir.path()) else {
        panic!("valid");
    };
    let after = with_set(&before, "review.consolidate", &json!("none")).expect("set");
    let layout = Layout::of(dir.path());
    let (edited, laid_out) =
        rewritten_at(&layout, Some(text), &changes(Some(&before), &after), &after);
    assert!(!laid_out, "{edited}");
    assert_eq!(edited, text.replace("jev #", "none #"));
}

#[test]
fn a_list_replaced_that_would_drop_an_unread_field_lays_the_file_out() {
    let text = "version: 2\nstages:\n  - uses: builtin/execution\n    checks:\n      - name: unit\n        run: make test\n        later: 2 # a newer devflow reads this\n";
    let before = crate::config::parse(text).expect("valid");
    let after = with_set(
        &before,
        "stages.execution.checks",
        &json!([{ "name": "unit", "run": "make test" }, { "name": "lint", "run": "make lint" }]),
    )
    .expect("set");
    let (edited, laid_out) = rewritten(Some(text), &changes(Some(&before), &after), &after);
    assert!(laid_out, "{edited}");
}

const LISTED: &str = "\
# Ours.
version: 2
enabled: true
stages:
  - uses: builtin/plan
    approve: person   # always
  - uses: builtin/review
    enabled: true
  - uses: builtin/completion
    gate: devflow-done
review:
  # Who reads it.
  attack: release
  block_on: [critical, high]
";

#[test]
fn an_attack_said_by_its_older_name_moves_to_its_stage_in_place() {
    let before = crate::config::parse(LISTED).expect("valid");
    assert_eq!(before.stages.attack.run, crate::config::AttackRun::Release);
    let after = with_set(
        &before,
        "stages.attack.test",
        &json!("npm test -- \"$DEVFLOW_EXPLOIT\""),
    )
    .expect("set");
    let (text, laid_out) = rewritten(Some(LISTED), &changes(Some(&before), &after), &after);
    assert!(!laid_out, "{text}");
    assert_eq!(
        text,
        LISTED
            .replace(
                "  - uses: builtin/completion\n",
                "  - uses: builtin/attack\n    run: release\n    test: \"npm test -- \\\"$DEVFLOW_EXPLOIT\\\"\"\n  - uses: builtin/completion\n",
            )
            .replace("  attack: release\n", "")
    );
    assert_eq!(crate::config::parse(&text), Ok(after));
}

#[test]
fn a_stage_the_list_lacks_is_added_where_the_flow_runs_it() {
    let flow = LISTED.replace("  attack: release\n", "");
    let before = crate::config::parse(&flow).expect("valid");
    let after = with_set(&before, "stages.attack.run", &json!("release")).expect("set");
    let (text, laid_out) = rewritten(Some(&flow), &changes(Some(&before), &after), &after);
    assert!(!laid_out, "{text}");
    assert!(
        text.contains("    enabled: true\n  - uses: builtin/attack\n    run: release\n  - uses: builtin/completion\n"),
        "{text}"
    );
    assert!(
        text.starts_with("# Ours.\n")
            && text.contains("# always")
            && text.contains("# Who reads it.")
    );
    assert_eq!(crate::config::parse(&text), Ok(after));
}

#[test]
fn a_detached_tree_without_the_file_follows_its_main_checkouts_folder() {
    let main = project(None);
    let root = main.path();
    std::fs::create_dir_all(root.join(LEGACY)).expect("folder");
    std::fs::write(root.join(LEGACY).join("devflow.yaml"), "version: 2\n").expect("write");
    let git = |args: &[&str]| {
        let ok = std::process::Command::new("git")
            .args(args)
            .current_dir(root)
            .status()
            .is_ok_and(|status| status.success());
        assert!(ok, "git {args:?}");
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "test@example.invalid"]);
    git(&["config", "user.name", "Test"]);
    git(&["config", "commit.gpgsign", "false"]);
    // devpit's folder is kept out of git, as a project may.
    std::fs::write(root.join(".git/info/exclude"), ".devpit/\n").expect("exclude");
    std::fs::write(root.join("README.md"), "# shop\n").expect("readme");
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "first"]);
    let head = crate::git::head_of(root).expect("head");
    let tree = tempfile::tempdir().expect("tree");
    let at = tree.path().join("attack");
    crate::git::add_detached(root, &at, &head).expect("detached");
    assert!(!at.join(LEGACY).exists());
    assert_eq!(dir(&at), LEGACY);
    assert_eq!(file(&at), crate::locate::DEVPIT);
    assert_eq!(
        crate::attack::threat_model_path(&at),
        format!("{LEGACY}/threat-model.md")
    );
    crate::git::remove_detached(root, &at);
}

#[test]
fn a_stage_added_to_a_file_with_crlf_ends_its_lines_the_same() {
    let flow = LISTED
        .replace("  attack: release\n", "")
        .replace('\n', "\r\n");
    let before = crate::config::parse(&flow).expect("valid");
    let after = with_set(&before, "stages.attack.run", &json!("release")).expect("set");
    let (text, laid_out) = rewritten(Some(&flow), &changes(Some(&before), &after), &after);
    assert!(!laid_out, "{text}");
    assert!(text.contains("builtin/attack\r\n"), "{text:?}");
    assert!(
        !text.replace("\r\n", "").contains('\n'),
        "mixed endings: {text:?}"
    );
}
