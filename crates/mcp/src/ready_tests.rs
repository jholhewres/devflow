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

    // What devflow found is said, not asked: the question is its message.
    let (message, schema) = wanted.question(&project);
    assert_eq!(schema["properties"], json!({}), "{schema}");
    for said in [
        "switches devflow on here",
        "`npx jest \"$DEVFLOW_EXPLOIT\"` (from package.json",
        "No sandbox here",
        "declining changes nothing",
    ] {
        assert!(message.contains(said), "{said}: {message}");
    }
    assert!(
        !message.contains("budget") && !message.contains("US$"),
        "{message}"
    );

    let applied = apply(
        &project,
        &consent,
        &wanted,
        &Map::new(),
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
    assert!(attack.budget.is_empty(), "no budget is written");
    assert!(!text.contains("budget"), "{text}");
    assert!(consent.made(&project.root, devflow_engine::Ask::Enable));
    let given = consent.given(&project.root);
    assert_eq!(given[0].what, "enabled");
    assert_eq!(given[0].how, How::Elicitation);
    assert_eq!(given[0].asked_for, "attack");

    let again = super::wanted(&project, &consent, OsStr::new(NOTHING), false).unwrap();
    assert!(!again.needed() && !again.optional(), "{again:?}");
}

#[test]
fn an_answer_that_does_not_read_writes_nothing() {
    // No runner found: the command is the one field.
    let (dir, project) = repo(&[(".devpit/devflow/devflow.yaml", &devpits())]);
    let consent = Consent::at(&dir.path().join("home"));
    let wanted = wanted(&project, &consent, OsStr::new(NOTHING), false).unwrap();
    for said in [
        json!({ "test": "x".repeat(501) }),
        json!({ "test": "make exploit\nrm -rf ." }),
        json!({ "test": 7 }),
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
        assert!(refused.to_string().contains("test"), "{refused}");
        assert_eq!(
            std::fs::read_to_string(dir.path().join(".devpit/devflow/devflow.yaml")).unwrap(),
            devpits()
        );
        assert!(!consent.made(&project.root, devflow_engine::Ask::Enable));
        assert!(consent.given(&project.root).is_empty());
    }
}

#[test]
fn the_command_is_asked_only_when_none_is_found() {
    let (dir, project) = repo(&[(".devpit/devflow/devflow.yaml", &devpits())]);
    let consent = Consent::at(&dir.path().join("home"));
    let wanted = wanted(&project, &consent, OsStr::new(NOTHING), false).unwrap();
    let (_, schema) = wanted.question(&project);
    let fields = schema["properties"].as_object().unwrap();
    assert_eq!(fields.keys().collect::<Vec<_>>(), ["test"], "{schema}");
    assert!(fields["test"].get("default").is_none());
    apply(
        &project,
        &consent,
        &wanted,
        &answer(json!({ "test": "make exploit EXPLOIT=\"$DEVFLOW_EXPLOIT\"" })),
        How::Elicitation,
        at(),
    )
    .unwrap();
    assert_eq!(
        config(&project).stages.attack.test.as_deref(),
        Some("make exploit EXPLOIT=\"$DEVFLOW_EXPLOIT\"")
    );
}

#[test]
fn the_image_is_said_when_found_and_asked_only_where_docker_runs_without_one() {
    let (dir, project) = repo(&[(".devpit/devflow/devflow.yaml", &devpits())]);
    let consent = Consent::at(&dir.path().join("home"));
    let mut wanted = wanted(&project, &consent, OsStr::new(NOTHING), false).unwrap();
    wanted.test = None;

    // Found for the project's runner: said, and written on a yes.
    wanted.image = Some("node:22".to_owned());
    wanted.sandbox = Some("bwrap".to_owned());
    let (message, schema) = wanted.question(&project);
    assert_eq!(schema["properties"], json!({}), "{schema}");
    assert!(
        message.contains("sets the docker image to node:22"),
        "{message}"
    );
    assert!(
        message.contains("Exploits run in bwrap, offline"),
        "{message}"
    );

    // Docker is the sandbox and nothing was found: the one field.
    wanted.image = Some(String::new());
    wanted.sandbox = Some("docker".to_owned());
    let (_, schema) = wanted.question(&project);
    assert!(schema["properties"]["image"].is_object(), "{schema}");
    let refused = apply(
        &project,
        &consent,
        &wanted,
        &answer(json!({ "image": "--privileged" })),
        How::Elicitation,
        at(),
    )
    .expect_err("not an image");
    assert!(refused.to_string().contains("image"), "{refused}");
    apply(
        &project,
        &consent,
        &wanted,
        &answer(json!({ "image": "python:3.12" })),
        How::Elicitation,
        at(),
    )
    .unwrap();
    assert_eq!(
        config(&project).stages.attack.image.as_deref(),
        Some("python:3.12")
    );

    // bwrap runs it: no image is asked.
    wanted.sandbox = Some("bwrap".to_owned());
    let (_, schema) = wanted.question(&project);
    assert_eq!(schema["properties"], json!({}), "{schema}");
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
        &answer(json!({ "test": "cargo test --test exploit" })),
        How::Elicitation,
        at(),
    )
    .unwrap();
    let config = config(&project);
    assert!(config.enabled);
    assert!(config.stages_on().contains(&"attack"));
    let found = match &wanted.test {
        Some(Some(found)) => found.command.clone(),
        Some(None) => "cargo test --test exploit".to_owned(),
        None => panic!("the command was wanted"),
    };
    assert_eq!(config.stages.attack.test.as_deref(), Some(found.as_str()));
    assert!(config.stages.attack.budget.is_empty());
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
        &Map::new(),
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
        &Map::new(),
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
        &answer(json!({ "test": "curl http://example.com", "targets": true })),
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
    assert!(fields.contains_key("targets"), "{schema}");
    for name in fields.keys() {
        assert!(
            ["test", "image", "targets"].contains(&name.as_str()),
            "{name}"
        );
    }
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

/// consent.json saying the question asked `parts` in the project.
fn answered(consent: &Consent, project: &Project, parts: &[&str]) {
    let parts: Vec<String> = parts.iter().map(|part| (*part).to_owned()).collect();
    consent
        .keep_answer(
            &project.root,
            &crate::consent::Answered {
                switched_on: true,
                targets: None,
                yeses: &["enabled", "stages.attack"],
                parts: &parts,
                how: How::Elicitation,
                asked_for: "attack",
                at: at(),
            },
        )
        .unwrap();
}

fn budget(run: Option<u64>, month: Option<u64>) -> Budget {
    Budget {
        run_cents: run,
        month_cents: month,
    }
}

#[test]
fn a_budget_the_old_question_prefilled_no_longer_holds_the_attack() {
    let (dir, project) = repo(&[(".devpit/devflow/devflow.yaml", &devpits())]);
    let consent = Consent::at(&dir.path().join("home"));
    let old = budget(Some(500), Some(5_000));
    // Written by hand: the question never asked it.
    assert_eq!(in_force(&project.root, &consent, old), old);
    assert!(prefilled(&project.root, &consent, old).is_empty());

    answered(
        &consent,
        &project,
        &["test", "sandbox", "run_usd", "month_usd"],
    );
    assert_eq!(prefilled(&project.root, &consent, old), old);
    assert!(in_force(&project.root, &consent, old).is_empty());
    assert_eq!(described(old), "US$ 5 per attack, US$ 50 a month");

    // What the person changed in the form, they chose: it still holds.
    let changed = budget(Some(1_000), Some(5_000));
    assert_eq!(
        in_force(&project.root, &consent, changed),
        budget(Some(1_000), None)
    );
}

/// devpit's file from before the attack was a stage: `review.attack`, its
/// older name.
fn devpits_older() -> String {
    devpits()
        .replace(
            "  - uses: builtin/attack\n    # The attack: devflow-security tries to exploit the change, and only a\n    # finding an exploit test confirmed holds the item. off, sensitive (a\n    # diff past small or on a sensitive path), per-item, or release (asked\n    # by name).\n    run: sensitive\n",
            "",
        )
        .replace("review:\n", "review:\n  attack: sensitive\n")
}

#[test]
fn a_yes_edits_devpits_older_file_in_place_and_keeps_its_words() {
    let older = devpits_older();
    let (dir, project) = repo(&[
        (".devpit/devflow/devflow.yaml", &older),
        (
            "package.json",
            "{ \"devDependencies\": { \"jest\": \"29\" } }",
        ),
    ]);
    let consent = Consent::at(&dir.path().join("home"));
    let wanted = wanted(&project, &consent, OsStr::new(NOTHING), false).unwrap();
    apply(
        &project,
        &consent,
        &wanted,
        &Map::new(),
        How::Elicitation,
        at(),
    )
    .unwrap();
    let text = std::fs::read_to_string(dir.path().join(".devpit/devflow/devflow.yaml")).unwrap();
    // Every comment devpit wrote is where it was; none of devflow's own.
    for line in older
        .lines()
        .filter(|line| line.trim_start().starts_with('#'))
    {
        assert!(text.contains(line), "{line} kept:\n{text}");
    }
    for devflows in [".devflow/", "served by devflow's MCP"] {
        assert!(!text.contains(devflows), "{devflows}:\n{text}");
    }
    let attack = config(&project).stages.attack;
    assert_eq!(attack.run, devflow_engine::config::AttackRun::Sensitive);
    assert_eq!(
        attack.test.as_deref(),
        Some("npx jest \"$DEVFLOW_EXPLOIT\"")
    );
    assert!(!text.contains("  attack: sensitive"), "said once:\n{text}");
}

#[test]
fn an_image_bwrap_does_not_need_is_neither_asked_nor_counted_as_answered() {
    let (dir, project) = repo(&[(".devpit/devflow/devflow.yaml", &devpits())]);
    let consent = Consent::at(&dir.path().join("home"));
    let mut wanted = wanted(&project, &consent, OsStr::new(NOTHING), false).unwrap();
    wanted.test = None;
    wanted.switch = false;
    wanted.image = Some(String::new());
    wanted.sandbox = Some("bwrap".to_owned());
    assert!(!wanted.needed() && !wanted.optional(), "{wanted:?}");
    assert!(!wanted.parts().contains(&"image".to_owned()));
}

#[cfg(unix)]
#[test]
fn a_docker_sandbox_set_with_no_image_asks_for_one() {
    use std::os::unix::fs::PermissionsExt;
    let yaml = devpits().replace(
        "    run: sensitive\n",
        "    run: sensitive\n    sandbox: docker\n",
    );
    let (dir, project) = repo(&[(".devpit/devflow/devflow.yaml", &yaml)]);
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(bin.join("docker"), "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(bin.join("docker"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let consent = Consent::at(&dir.path().join("home"));
    let wanted = wanted(&project, &consent, bin.as_os_str(), false).unwrap();
    assert_eq!(wanted.sandbox.as_deref(), Some("docker"));
    let (message, schema) = wanted.question(&project);
    assert!(schema["properties"]["image"].is_object(), "{schema}");
    assert!(message.contains("Exploits run in docker"), "{message}");
}
