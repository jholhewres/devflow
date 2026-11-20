use std::ffi::OsStr;
use std::path::Path;
use std::time::{Duration, SystemTime};

use devflow_engine::folder::State;
use serde_json::{json, Map, Value};

use super::*;
use crate::consent::{Consent, How};
use crate::project::Project;

/// What devpit writes, as its setup does (the engine's golden file), then
/// switched on by the person's click in its app.
pub(crate) fn devpits() -> String {
    include_str!(
        "../../engine/tests/fixtures/devpit-golden/setup-file_devpit_devflow_devflow_yaml.txt"
    )
    .replace("enabled: false\n", "enabled: true\n")
}

fn repo(files: &[(&str, &str)]) -> (tempfile::TempDir, Project) {
    let dir = tempfile::tempdir().unwrap();
    for (name, body) in files {
        let at = dir.path().join(name);
        std::fs::create_dir_all(at.parent().unwrap()).unwrap();
        std::fs::write(at, body).unwrap();
    }
    let project = Project::at(dir.path());
    (dir, project)
}

/// No sandbox and no docker on this PATH: the same on every machine.
const NOTHING: &str = "";

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_795_000_000)
}

fn answer(fields: Value) -> Map<String, Value> {
    fields.as_object().unwrap().clone()
}

fn config(project: &Project) -> devflow_engine::config::Config {
    match project.read() {
        State::Valid(_, config) => *config,
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_project_devpit_switched_on_is_asked_once_and_keeps_devpits_words() {
    let (dir, project) = repo(&[
        (".devpit/devflow/devflow.yaml", &devpits()),
        (
            "package.json",
            "{ \"devDependencies\": { \"jest\": \"29\" } }",
        ),
    ]);
    let consent = Consent::at(&dir.path().join("home"));
    let wanted = wanted(&project, &consent, OsStr::new(NOTHING), false).unwrap();
    assert!(wanted.switch, "devflow's own switch here is off");
    assert!(!wanted.setup && !wanted.stage);
    assert!(wanted.needed());

    let (_, schema) = wanted.question(&project);
    let fields = &schema["properties"];
    assert_eq!(fields["switch_on"]["default"], true);
    assert_eq!(fields["test"]["default"], "npx jest \"$DEVFLOW_EXPLOIT\"");
    assert_eq!(fields["run_usd"]["default"], RUN_USD);
    assert_eq!(fields["month_usd"]["default"], MONTH_USD);
    assert!(fields["sandbox"]["enum"].to_string().contains("bwrap"));
    assert!(fields.get("targets").is_none(), "no target listed");

    let applied = apply(
        &project,
        &consent,
        &wanted,
        &answer(json!({ "switch_on": true, "test": "npx jest \"$DEVFLOW_EXPLOIT\"", "sandbox": "auto", "run_usd": 3, "month_usd": 30 })),
        How::Elicitation,
        at(),
    )
    .unwrap();
    assert!(applied.switched);
    let text = std::fs::read_to_string(dir.path().join(".devpit/devflow/devflow.yaml")).unwrap();
    for kept in [
        "# Switched on by the person's click in the devpit app, never by an agent.",
        "# The attack: devflow-security tries to exploit the change, and only a",
        "publish: board   # board | jira | linear | github",
        "run: sh .devpit/devflow/scripts/check-unit.sh",
    ] {
        assert!(text.contains(kept), "{kept} kept:\n{text}");
    }
    let attack = config(&project).stages.attack;
    assert_eq!(
        attack.test.as_deref(),
        Some("npx jest \"$DEVFLOW_EXPLOIT\"")
    );
    assert_eq!(attack.sandbox, None, "auto is not written");
    assert_eq!(attack.budget.run_cents, Some(300));
    assert_eq!(attack.budget.month_cents, Some(3000));
    assert!(consent.made(&project.root, devflow_engine::Ask::Enable));
    let given = consent.given(&project.root);
    assert_eq!(given[0].what, "enabled");
    assert_eq!(given[0].how, How::Elicitation);
    assert_eq!(given[0].asked_for, "attack");

    let again = super::wanted(&project, &consent, OsStr::new(NOTHING), false).unwrap();
    assert!(!again.needed() && !again.optional(), "{again:?}");
}

#[test]
fn a_no_or_an_answer_that_does_not_read_writes_nothing() {
    let (dir, project) = repo(&[(".devpit/devflow/devflow.yaml", &devpits())]);
    let consent = Consent::at(&dir.path().join("home"));
    let wanted = wanted(&project, &consent, OsStr::new(NOTHING), false).unwrap();
    for (said, why) in [
        (json!({ "switch_on": false, "run_usd": 3 }), "off"),
        (json!({ "switch_on": true, "run_usd": -1 }), "run_usd"),
        (
            json!({ "switch_on": true, "month_usd": "lots" }),
            "month_usd",
        ),
        (json!({ "switch_on": true, "sandbox": "vm" }), "sandbox"),
        (
            json!({ "switch_on": true, "test": "x".repeat(501) }),
            "test",
        ),
    ] {
        let refused = apply(
            &project,
            &consent,
            &wanted,
            &answer(said),
            How::Elicitation,
            at(),
        )
        .expect_err("refused");
        assert!(matches!(refused, NotApplied::Unread(_)), "{refused:?}");
        let refused = refused.to_string();
        assert!(refused.contains(why), "{why}: {refused}");
        assert_eq!(
            std::fs::read_to_string(dir.path().join(".devpit/devflow/devflow.yaml")).unwrap(),
            devpits()
        );
        assert!(!consent.made(&project.root, devflow_engine::Ask::Enable));
        assert!(consent.given(&project.root).is_empty());
    }
}

#[test]
fn a_project_with_nothing_set_up_gets_the_recommended_setup_with_the_attack() {
    let (dir, project) = repo(&[("Cargo.toml", "[package]\nname = \"shop\"\n")]);
    let consent = Consent::at(&dir.path().join("home"));
    let wanted = wanted(&project, &consent, OsStr::new(NOTHING), false).unwrap();
    assert!(wanted.setup && wanted.switch);
    let (message, _) = wanted.question(&project);
    assert!(message.contains("devflow.yaml"), "{message}");
    apply(
        &project,
        &consent,
        &wanted,
        &answer(json!({ "switch_on": true, "test": "cargo test --test x", "run_usd": 2, "month_usd": 20 })),
        How::Elicitation,
        at(),
    )
    .unwrap();
    let config = config(&project);
    assert!(config.enabled);
    assert!(config.stages_on().contains(&"attack"));
    assert_eq!(
        config.stages.attack.test.as_deref(),
        Some("cargo test --test x")
    );
    assert!(consent.made(&project.root, devflow_engine::Ask::Enable));
}

#[test]
fn an_attack_stage_switched_off_is_switched_on_for_attacks_asked_by_name() {
    let off = devpits().replace("    run: sensitive\n", "    run: off\n");
    let (dir, project) = repo(&[(".devpit/devflow/devflow.yaml", &off)]);
    let consent = Consent::at(&dir.path().join("home"));
    consent
        .remember(&project.root, devflow_engine::Ask::Enable, true)
        .unwrap();
    let wanted = wanted(&project, &consent, OsStr::new(NOTHING), false).unwrap();
    assert!(wanted.stage && !wanted.switch);
    apply(
        &project,
        &consent,
        &wanted,
        &answer(json!({ "switch_on": true })),
        How::Terminal,
        at(),
    )
    .unwrap();
    let attack = config(&project).stages.attack;
    assert_eq!(attack.run, devflow_engine::config::AttackRun::Release);
}

#[test]
fn a_listed_target_is_asked_with_what_it_resolves_to_and_confirmed_only_when_ticked() {
    let yaml = format!(
        "{}security:\n  targets:\n    - http://127.0.0.1:8080\n    - http://no-such-service-here:8080\n",
        devpits()
    );
    let (dir, project) = repo(&[(".devpit/devflow/devflow.yaml", &yaml)]);
    let consent = Consent::at(&dir.path().join("home"));
    let wanted = wanted(&project, &consent, OsStr::new(NOTHING), false).unwrap();
    assert_eq!(
        wanted.targets,
        ["http://127.0.0.1:8080", "http://no-such-service-here:8080"]
    );
    let (_, schema) = wanted.question(&project);
    assert_eq!(schema["properties"]["targets"]["default"], false);
    assert!(schema["properties"]["targets"]["description"]
        .as_str()
        .unwrap()
        .contains("http://no-such-service-here:8080 (resolves to nothing here)"));

    apply(
        &project,
        &consent,
        &wanted,
        &answer(json!({ "switch_on": true })),
        How::Elicitation,
        at(),
    )
    .unwrap();
    assert!(
        consent.confirmed_targets(&project.root).is_empty(),
        "left unticked"
    );
    let wanted = super::wanted(&project, &consent, OsStr::new(NOTHING), false).unwrap();
    assert!(
        wanted.targets.is_empty(),
        "answered: not asked again through the client"
    );
    let wanted = super::wanted(&project, &consent, OsStr::new(NOTHING), true).unwrap();
    apply(
        &project,
        &consent,
        &wanted,
        &answer(json!({ "targets": true })),
        How::Elicitation,
        at(),
    )
    .unwrap();
    assert_eq!(
        consent.confirmed_targets(&project.root),
        ["http://127.0.0.1:8080", "http://no-such-service-here:8080"]
    );
    // What it resolves to is checked when an attack runs: nothing here, so
    // only the loopback address is in force.
    let config = config(&project);
    assert_eq!(
        crate::flow::targets_in_force(&project, &config, &consent),
        ["http://127.0.0.1:8080"]
    );
    assert!(consent
        .given(&project.root)
        .iter()
        .any(|one| one.what == "security.targets" && one.how == How::Elicitation));
}

#[test]
fn a_field_that_was_not_asked_is_not_read() {
    let (dir, project) = repo(&[(".devpit/devflow/devflow.yaml", &devpits())]);
    let consent = Consent::at(&dir.path().join("home"));
    let mut wanted = wanted(&project, &consent, OsStr::new(NOTHING), false).unwrap();
    wanted.test = None;
    apply(
        &project,
        &consent,
        &wanted,
        &answer(json!({ "switch_on": true, "test": "curl http://example.com", "targets": true })),
        How::Elicitation,
        at(),
    )
    .unwrap();
    assert_eq!(config(&project).stages.attack.test, None);
    assert!(Path::new(&project.root).is_dir());
}

/// What MCP lets a question ask: a flat form of strings, numbers and
/// booleans, each with only the keywords the spec names.
#[test]
fn the_question_is_a_flat_form_of_what_elicitation_allows() {
    let yaml = format!(
        "{}security:\n  targets:\n    - http://127.0.0.1:8080\n",
        devpits()
    );
    let (dir, project) = repo(&[
        (".devpit/devflow/devflow.yaml", &yaml),
        ("go.mod", "module example.com/shop\n"),
    ]);
    let consent = Consent::at(&dir.path().join("home"));
    let path = std::env::var_os("PATH").unwrap_or_default();
    let wanted = wanted(&project, &consent, &path, false).unwrap();
    let (message, schema) = wanted.question(&project);
    assert!(!message.is_empty());
    assert_eq!(schema["type"], "object");
    let allowed = [
        "type",
        "title",
        "description",
        "default",
        "enum",
        "enumNames",
        "minLength",
        "maxLength",
        "format",
        "minimum",
        "maximum",
    ];
    let fields = schema["properties"].as_object().unwrap();
    assert!(fields.len() >= 5, "{schema}");
    for (name, field) in fields {
        let kind = field["type"].as_str().unwrap_or_default();
        assert!(
            ["string", "number", "integer", "boolean"].contains(&kind),
            "{name}: {field}"
        );
        for key in field.as_object().unwrap().keys() {
            assert!(allowed.contains(&key.as_str()), "{name}.{key}");
        }
    }
}
