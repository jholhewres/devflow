use serde_json::json;

use super::*;
use crate::config::{parse, Report};
use crate::detect::Found;

fn detected() -> Detected {
    Detected {
        test: vec![Found {
            command: "make test".into(),
            source: "Makefile:1".into(),
            report: Report::Junit,
            unavailable: None,
        }],
        e2e: vec![],
        lint: vec![],
        typecheck: vec![],
        nested: vec![],
        e2e_tools: vec![],
        clis: vec![],
        decisions_key: true,
        decisions_opted_out: false,
        glossary: None,
        adrs: vec![],
        hints: Default::default(),
    }
}

fn valid(text: &str) -> State {
    State::Valid(text.to_owned(), Box::new(parse(text).expect("valid")))
}

fn asked(set: serde_json::Value) -> Map<String, Value> {
    set.as_object().cloned().unwrap_or_default()
}

#[test]
fn a_setup_never_switches_devflow_on_or_decisions_to_enforce() {
    let proposal = setup(
        &State::Missing,
        Preset::Recommended,
        &asked(json!({ "enabled": true, "decisions.mode": "enforce" })),
        &detected(),
    )
    .expect("setup");
    assert!(!proposal.config.enabled);
    assert_eq!(proposal.config.decisions.mode, Mode::Shadow);
    assert_eq!(proposal.asks, [Ask::Enable, Ask::Enforce]);
    assert!(proposal.yaml.contains("\nenabled: false\n"));
}

#[test]
fn a_setup_folds_the_answers_in_and_scripts_every_check() {
    let proposal = setup(
        &State::Missing,
        Preset::Recommended,
        &asked(json!({
            "stages.execution.checks": [{ "name": "unit", "run": "tox -e py311", "report": "junit" }]
        })),
        &detected(),
    )
    .expect("setup");
    let check = &proposal.config.stages.execution.checks[0];
    assert_eq!(check.run, "sh .devpit/devflow/scripts/check-unit.sh");
    assert_eq!(proposal.scripts[0].command, "tox -e py311");
    assert!(proposal
        .files
        .iter()
        .any(|file| file.path == ".devpit/devflow/scripts/check-unit.sh"));
    assert_eq!(parse(&proposal.yaml), Ok(proposal.config.clone()));
}

#[test]
fn a_setup_run_again_leaves_devflow_on() {
    let on = valid("version: 1\nenabled: true\n");
    let proposal = setup(&on, Preset::Custom, &Map::new(), &detected()).expect("setup");
    assert!(proposal.config.enabled);
    assert!(proposal.asks.is_empty());
}

#[test]
fn switching_on_through_a_change_is_asked_of_the_person_and_not_written() {
    let off = valid("version: 1\nenabled: false\n");
    let proposal = set(&off, "enabled", &json!(true)).expect("set");
    assert_eq!(proposal.asks, [Ask::Enable]);
    assert!(proposal.changes.is_empty());
    assert!(!proposal.config.enabled);
    let enforce = set(&off, "decisions.mode", &json!("enforce")).expect("set");
    assert_eq!(enforce.asks, [Ask::Enforce]);
    assert_eq!(enforce.config.decisions.mode, Mode::Shadow);
}

#[test]
fn switching_off_is_written_at_once() {
    let on = valid("version: 1\nenabled: true # on\n");
    let proposal = set(&on, "enabled", &json!(false)).expect("set");
    assert!(proposal.asks.is_empty());
    assert_eq!(proposal.yaml, "version: 1\nenabled: false # on\n");
}

#[test]
fn the_persons_click_writes_what_was_asked_in_place() {
    let off = valid("version: 1\n# ours\nenabled: false\n");
    let on = switched(&off, Ask::Enable).expect("switched");
    assert_eq!(on.yaml, "version: 1\n# ours\nenabled: true\n");
    assert!(!on.laid_out);
    assert!(switched(&State::Missing, Ask::Enable).is_err());
}

#[test]
fn an_invalid_file_is_fixed_one_field_at_a_time() {
    let text = "version: 1\nstages:\n  plan:\n    approve: robot   # who?\n";
    let state = State::Invalid(Some(text.into()), parse(text).expect_err("invalid"));
    let fixed = set(&state, "stages.plan.approve", &json!("person")).expect("fixed");
    assert_eq!(fixed.yaml, text.replace("robot", "person"));
    assert!(set(&State::Missing, "enabled", &json!(false)).is_err());
}

/// The person switched Devflow on between an agent's preview and its apply.
#[test]
fn a_setup_over_a_file_the_click_changed_is_not_the_one_previewed() {
    let preview = setup(
        &State::Missing,
        Preset::Recommended,
        &Map::new(),
        &detected(),
    )
    .expect("preview");
    let again = setup(
        &State::Missing,
        Preset::Recommended,
        &Map::new(),
        &detected(),
    )
    .expect("again");
    assert_eq!(again.changed_since(&preview), None);

    let written = valid(&preview.yaml);
    let clicked = switched(&written, Ask::Enable).expect("clicked");
    let applied = setup(
        &valid(&clicked.yaml),
        Preset::Recommended,
        &Map::new(),
        &detected(),
    )
    .expect("apply");
    assert_eq!(
        applied.changed_since(&preview),
        Some(vec!["enabled".to_owned()])
    );
}

#[test]
fn a_setup_run_again_over_the_persons_file_keeps_their_comments() {
    let first = setup(
        &State::Missing,
        Preset::Recommended,
        &Map::new(),
        &detected(),
    )
    .expect("first");
    let edited = first.yaml.replace(
        "enabled: false\n",
        "enabled: false   # ours: on next sprint\n# and a note of our own\n",
    );
    let again = setup(
        &valid(&edited),
        Preset::Recommended,
        &Map::new(),
        &detected(),
    )
    .expect("again");
    assert!(!again.laid_out, "{}", again.yaml);
    assert_eq!(again.yaml, edited);

    let set = setup(
        &valid(&edited),
        Preset::Recommended,
        &asked(json!({ "review.block_on": ["critical"] })),
        &detected(),
    )
    .expect("a list changed");
    assert!(set.laid_out, "a list is more than a word");
}

#[test]
fn a_version_1_file_stays_version_1_after_an_unrelated_change() {
    let v1 = valid("version: 1\n# ours\nenabled: false\nreview:\n  consolidate: none\n");
    let changed = set(&v1, "review.consolidate", &json!("agent")).expect("changed");
    assert_eq!(
        changed.yaml,
        "version: 1\n# ours\nenabled: false\nreview:\n  consolidate: agent\n"
    );
    let listed = set(&v1, "review.block_on", &json!(["critical"])).expect("laid out");
    assert!(listed.yaml.contains("\nversion: 1\n"), "{}", listed.yaml);
    assert_eq!(
        parse(&listed.yaml).expect("reads").version,
        crate::config::V1
    );
}

#[test]
fn a_check_added_by_a_change_gets_a_script_and_one_already_there_keeps_its_command() {
    let text = "version: 1\nstages:\n  execution:\n    checks:\n      - name: unit\n        run: make test\n";
    let checks = json!([
        { "name": "unit", "run": "make test" },
        { "name": "lint", "run": "make lint" },
    ]);
    let added = set(&valid(text), "stages.execution.checks", &checks).expect("added");
    let runs: Vec<&str> = added
        .config
        .stages
        .execution
        .checks
        .iter()
        .map(|check| check.run.as_str())
        .collect();
    assert_eq!(
        runs,
        ["make test", "sh .devpit/devflow/scripts/check-lint.sh"]
    );
    let paths: Vec<&str> = added.files.iter().map(|file| file.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            ".devpit/devflow/devflow.yaml",
            ".devpit/devflow/scripts/check-lint.sh"
        ]
    );
}
