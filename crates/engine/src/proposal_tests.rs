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
    assert_eq!(check.run, "sh .devflow/scripts/check-unit.sh");
    assert_eq!(proposal.scripts[0].command, "tox -e py311");
    assert!(proposal
        .files
        .iter()
        .any(|file| file.path == ".devflow/scripts/check-unit.sh"));
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
    assert!(!set.laid_out, "a list is edited in place too: {}", set.yaml);
    assert!(set
        .yaml
        .contains("# ours: on next sprint\n# and a note of our own\n"));
}

#[test]
fn a_version_1_file_stays_version_1_after_an_unrelated_change() {
    let v1 = valid("version: 1\n# ours\nenabled: false\nreview:\n  consolidate: none\n");
    let changed = set(&v1, "review.consolidate", &json!("agent")).expect("changed");
    assert_eq!(
        changed.yaml,
        "version: 1\n# ours\nenabled: false\nreview:\n  consolidate: agent\n"
    );
    let listed = set(&v1, "review.block_on", &json!(["critical"])).expect("in place");
    assert!(
        listed.yaml.starts_with("version: 1\n# ours\n"),
        "{}",
        listed.yaml
    );
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
    assert_eq!(runs, ["make test", "sh .devflow/scripts/check-lint.sh"]);
    let paths: Vec<&str> = added.files.iter().map(|file| file.path.as_str()).collect();
    assert_eq!(
        paths,
        [".devflow/devflow.yaml", ".devflow/scripts/check-lint.sh"]
    );
}

#[test]
fn the_attack_and_its_targets_are_set_as_any_field_and_read_back() {
    let state = valid("version: 2\nenabled: true\n");
    let attack = set(&state, "review.attack", &Value::from("sensitive")).expect("attack");
    assert!(attack.yaml.contains("attack: sensitive"), "{}", attack.yaml);
    assert_eq!(
        attack.config.review.attack.as_ref().map(|one| one.run),
        Some(crate::config::AttackRun::Sensitive)
    );
    let targets = set(
        &state,
        "security.targets",
        &serde_json::json!(["http://localhost:8080"]),
    )
    .expect("targets");
    assert!(
        targets.yaml.contains("- http://localhost:8080"),
        "{}",
        targets.yaml
    );
    assert_eq!(
        crate::config::parse(&targets.yaml)
            .expect("again")
            .security
            .targets,
        ["http://localhost:8080"]
    );
    let wrong = set(
        &state,
        "security.targets",
        &serde_json::json!(["http://localhost@evil.com"]),
    )
    .expect_err("a user before the host");
    assert!(wrong.message.contains("`@`"), "{wrong}");
}

#[test]
fn a_model_is_set_by_stage_and_by_reviewer_and_a_wrong_one_is_refused() {
    let state = valid(
        "version: 2\nstages:\n  - uses: builtin/plan\n  - uses: builtin/execution\nreview:\n  reviewers:\n    - { agent: claude, persona: devflow-security }\n    - { agent: codex, persona: devflow-spec }\n",
    );
    let plan = set(&state, "stages.plan.model", &json!("large")).expect("a stage");
    let written = parse(&plan.yaml).expect("the file written");
    assert_eq!(
        written.stages.plan.model.as_deref(),
        Some("large"),
        "{}",
        plan.yaml
    );
    let reviewer = set(
        &state,
        "review.reviewers.devflow-security.model",
        &json!("claude-opus-5-5"),
    )
    .expect("a reviewer by its persona");
    assert_eq!(
        reviewer.config.review.reviewers[0].model.as_deref(),
        Some("claude-opus-5-5"),
        "{}",
        reviewer.yaml
    );
    assert!(
        reviewer.yaml.contains("model: claude-opus-5-5"),
        "{}",
        reviewer.yaml
    );

    let case = set(&state, "stages.plan.model", &json!("Large")).expect_err("a tier's case");
    assert!(case.message.contains("`large`"), "{case}");
    let flag = set(&state, "stages.execution.model", &json!("-x")).expect_err("a flag");
    assert!(flag.message.contains("small, default or large"), "{flag}");
    let stage = set(&state, "stages.nowhere.model", &json!("small")).expect_err("no such stage");
    assert!(
        stage.message.contains("no stage called `nowhere`"),
        "{stage}"
    );
    let persona = set(
        &state,
        "review.reviewers.devflow-nobody.model",
        &json!("small"),
    )
    .expect_err("no such reviewer");
    assert!(persona.message.contains("`devflow-nobody`"), "{persona}");

    let twice = valid(
        "version: 2\nreview:\n  reviewers:\n    - { agent: claude, persona: devflow-all }\n    - { agent: codex, persona: devflow-all }\n",
    );
    let which = set(
        &twice,
        "review.reviewers.devflow-all.model",
        &json!("small"),
    )
    .expect_err("two reviewers read as devflow-all");
    assert!(which.message.contains("review.reviewers.1"), "{which}");
}

#[test]
fn a_model_written_by_hand_survives_a_change_that_lays_the_file_out_again() {
    let state = valid(
        "version: 2\nstages:\n  - uses: builtin/plan\n    model: large\n  - uses: builtin/execution\nmodels: quality\nreview:\n  analysis: { model: claude-opus-5-5 }\n  reviewers:\n    - { agent: claude, persona: devflow-security }\n",
    );
    let changed = set(
        &state,
        "review.reviewers.devflow-security.model",
        &json!("small"),
    )
    .expect("a reviewer's model");
    let written = parse(&changed.yaml).expect("the file written");
    assert_eq!(
        written.stages.plan.model.as_deref(),
        Some("large"),
        "{}",
        changed.yaml
    );
    assert_eq!(
        written.models,
        Some(crate::config::Models::Quality),
        "{}",
        changed.yaml
    );
    assert_eq!(
        written.review.analysis.and_then(|one| one.model).as_deref(),
        Some("claude-opus-5-5"),
        "{}",
        changed.yaml
    );
}

#[test]
fn a_check_is_named_by_its_name_in_a_path() {
    let state = valid(
        "version: 2\nstages:\n  - uses: builtin/execution\n    checks:\n      - { name: unit, run: make test }\n",
    );
    let changed = set(
        &state,
        "stages.execution.checks.unit.run",
        &json!("cargo test"),
    )
    .expect("a check by its name");
    assert_eq!(changed.config.stages.execution.checks[0].run, "cargo test");
}
