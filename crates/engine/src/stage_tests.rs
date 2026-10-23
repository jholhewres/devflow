use serde_json::json;

use super::*;
use crate::config::parse;
use crate::gate::{checked, Looked};

const FLOW: &str = "version: 2
stages:
  - uses: builtin/execution
  - uses: project/pr
    gate: { command: \"./scripts/pr-checklist.sh\" }
  - uses: project/notes
";

fn missing(
    config: &Config,
    stages: &[(String, Option<(String, Value)>)],
    changed: Option<&str>,
) -> Vec<String> {
    checked(&Looked {
        config,
        card: "card_1",
        criteria: &[],
        run: None,
        review: None,
        changed,
        stages,
        unreviewed: None,
        no_code: false,
    })
    .missing
    .into_iter()
    .filter(|item| item.contains("stage `"))
    .collect()
}

#[test]
fn the_card_is_not_done_until_each_own_stage_passed_its_gate() {
    let config = parse(FLOW).expect("reads");
    let (step, gate) = gated(&config, "pr").expect("a gated stage");
    assert_eq!(step.uses, "project/pr");
    assert_eq!(
        gate,
        &StageGate::Command("./scripts/pr-checklist.sh".into())
    );
    assert!(gated(&config, "notes")
        .expect_err("no gate")
        .contains("no gate"));
    assert!(
        gated(&config, "execution").is_err(),
        "a built-in stage is not an own one"
    );

    let none = missing(&config, &[], None);
    assert_eq!(
        none.len(),
        1,
        "a stage without a gate holds nothing: {none:?}"
    );
    assert!(none[0].contains("`stage`"), "{none:?}");

    let run = "20261011T120000Z".to_owned();
    let failed = recorded("pr", gate, false, &run, &["exit 1".into()]);
    let held = missing(&config, &[("pr".into(), Some((run.clone(), failed)))], None);
    assert!(held[0].contains("failed"), "{held:?}");

    let passed = recorded("pr", gate, true, &run, &[]);
    let seen = [("pr".into(), Some((run, passed)))];
    assert!(missing(&config, &seen, None).is_empty());
    let stale = missing(&config, &seen, Some("20261011T130000Z"));
    assert!(stale[0].contains("before the last change"), "{stale:?}");
}

#[test]
fn a_layers_command_is_confirmed_again_when_it_or_its_commit_changes() {
    let first = fingerprint("git@x:acme/flow.git", "aaa", "./scripts/pr.sh");
    assert_eq!(
        first,
        fingerprint("git@x:acme/flow.git", "aaa", "./scripts/pr.sh")
    );
    assert_ne!(
        first,
        fingerprint("git@x:acme/flow.git", "bbb", "./scripts/pr.sh")
    );
    assert_ne!(
        first,
        fingerprint("git@x:acme/flow.git", "aaa", "./scripts/pr.sh --all")
    );
    assert_eq!(
        recorded("pr", &StageGate::Rubric("ours".into()), true, "t", &[])["gate"],
        json!("rubric")
    );
}
