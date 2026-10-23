use serde_json::json;

use super::*;
use crate::config::{Approve, Report};
use crate::detect::{Cli, E2eTool, Found};

fn detected() -> Detected {
    let found = |command: &str, source: &str, report| Found {
        command: command.into(),
        source: source.into(),
        report,
        unavailable: None,
    };
    Detected {
        test: vec![
            found("make test", "Makefile:4", Report::Nothing),
            found("cargo test", "Cargo.toml:1", Report::Cargo),
        ],
        e2e: vec![found("pnpm run e2e", "package.json:6", Report::Nothing)],
        lint: vec![],
        typecheck: vec![],
        nested: vec![],
        e2e_tools: vec![E2eTool {
            name: "playwright".into(),
            source: "playwright.config.ts".into(),
            run: Some(crate::playwright::command("pnpm exec")),
        }],
        clis: vec![
            Cli {
                name: Agent::Claude,
                installed: true,
                signed_in: Some(false),
            },
            Cli {
                name: Agent::Codex,
                installed: true,
                signed_in: None,
            },
        ],
        decisions_key: true,
        decisions_opted_out: false,
        glossary: None,
        adrs: vec![],
        hints: Default::default(),
    }
}

#[test]
fn the_recommended_setup_is_built_from_what_was_detected() {
    let config = starting(Preset::Recommended, &detected());
    assert!(!config.enabled);
    assert_eq!(config.stages.briefing.approve, Approve::Person);
    assert_eq!(config.stages.plan.approve, Approve::Person);
    let checks = &config.stages.execution.checks;
    let ran: Vec<(&str, &str)> = checks
        .iter()
        .map(|check| (check.name.as_str(), check.run.as_str()))
        .collect();
    // With Playwright the E2E check runs Devflow's specs, and the project's
    // own E2E command is still called.
    assert_eq!(
        ran,
        [
            ("unit", "make test"),
            (
                "e2e",
                "pnpm exec playwright test --config .devpit/devflow/playwright.config.ts"
            ),
            ("e2e-suite", "pnpm run e2e"),
        ]
    );
    assert_eq!(checks[1].report, Report::Junit);
    assert_eq!(checks[1].evidence, [Evidence::Screenshots, Evidence::Video]);
    assert!(checks[2].evidence.is_empty());
    // Claude is signed out, so the reviewer is the next CLI that may review.
    assert_eq!(
        config.review.reviewers,
        [Reviewer {
            agent: Agent::Codex,
            persona: SECURITY.into(),
            model: None
        }]
    );
    assert_eq!(config.stages.completion.gate, "devflow-done");
    assert!(config.decisions.use_);
    assert_eq!(config.decisions.mode, Mode::Shadow);
}

#[test]
fn without_playwright_the_projects_e2e_command_is_the_e2e_check() {
    let mut found = detected();
    found.e2e_tools[0] = E2eTool {
        name: "cypress".into(),
        source: "cypress.config.ts".into(),
        run: None,
    };
    let config = starting(Preset::Recommended, &found);
    let e2e = &config.stages.execution.checks[1];
    assert_eq!(
        (e2e.name.as_str(), e2e.run.as_str()),
        ("e2e", "pnpm run e2e")
    );
    assert_eq!(e2e.evidence, [Evidence::Screenshots]);
    assert_eq!(config.stages.execution.checks.len(), 2);
}

#[test]
fn decisions_stay_off_without_a_key_or_with_the_project_opted_out() {
    let mut found = detected();
    found.decisions_opted_out = true;
    assert!(!starting(Preset::Recommended, &found).decisions.use_);
    found.decisions_key = false;
    found.decisions_opted_out = false;
    assert!(!starting(Preset::Recommended, &found).decisions.use_);
}

#[test]
fn custom_starts_from_the_defaults() {
    let mut defaults = Config::default();
    defaults.stages.plan.publish = Some(crate::config::Publish::Board);
    assert_eq!(starting(Preset::Custom, &detected()), defaults);
}

#[test]
fn a_field_a_list_item_and_a_whole_list_are_set_by_path() {
    let config = Config::default();
    let set = with_set(&config, "review.block_on", &json!(["critical"])).expect("set");
    assert_eq!(set.review.block_on, [crate::config::Severity::Critical]);
    let added = with_set(
        &config,
        "review.reviewers.0",
        &json!({ "agent": "cursor", "persona": "devflow-spec" }),
    )
    .expect("added");
    assert_eq!(added.review.reviewers[0].agent, Agent::Cursor);
    let renamed = with_set(
        &added,
        "review.reviewers.0.persona",
        &json!("devflow-standards"),
    )
    .expect("renamed");
    assert_eq!(renamed.review.reviewers[0].persona, "devflow-standards");
}

#[test]
fn a_path_that_is_not_in_the_schema_is_refused_by_name() {
    let config = Config::default();
    let invalid = with_set(&config, "stages.shipping.enabled", &json!(true)).expect_err("refused");
    assert_eq!(invalid.field, "stages.shipping");
    let wrong = with_set(&config, "stages.plan.approve", &json!("robot")).expect_err("refused");
    assert_eq!(wrong.field, "stages.plan.approve");
    assert!(with_set(&config, "version", &json!(2)).is_err());
    assert!(with_set(&config, "review.reviewers.3", &json!({})).is_err());
    assert!(with_set(&config, "review..block_on", &json!([])).is_err());
}

#[test]
fn a_change_lists_each_field_that_differs() {
    let before = Config::default();
    let after = with_set(&before, "stages.plan.approve", &json!("none")).expect("set");
    assert_eq!(
        changes(Some(&before), &after),
        [Change {
            path: "stages.plan.approve".into(),
            before: json!("person"),
            after: json!("none"),
        }]
    );
    let created = changes(None, &before);
    assert!(created
        .iter()
        .any(|one| one.path == "stages.briefing.approve"));
    assert!(created.iter().all(|one| one.before.is_null()));
}
