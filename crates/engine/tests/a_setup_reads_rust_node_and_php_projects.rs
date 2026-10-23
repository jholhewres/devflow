//! Detection over three small projects kept as files under `fixtures/`, and
//! the recommended setup each one gets.

use std::path::PathBuf;

use devflow_engine::config::{Agent, Evidence, Report};
use devflow_engine::detect::{detected, open, Cli, Detected, Machine};
use devflow_engine::preset::Preset;
use devflow_engine::{config, proposal, State};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn machine() -> Machine {
    Machine {
        clis: vec![Cli {
            name: Agent::Claude,
            installed: true,
            signed_in: Some(true),
        }],
        decisions_key: false,
        decisions_opted_out: false,
        ..Machine::default()
    }
}

fn said(found: &[devflow_engine::detect::Found]) -> Vec<(&str, &str, Report)> {
    found
        .iter()
        .map(|one| (one.command.as_str(), one.source.as_str(), one.report))
        .collect()
}

fn recommended(detected: &Detected) -> devflow_engine::Proposal {
    proposal::setup(
        &State::Missing,
        Preset::Recommended,
        &Default::default(),
        detected,
    )
    .expect("a setup")
}

#[test]
fn a_rust_project_tests_with_cargo_and_keeps_a_glossary() {
    let found = detected(&fixture("rust"), machine());
    assert_eq!(
        said(&found.test),
        [("cargo test", "Cargo.toml:2", Report::Cargo)]
    );
    assert_eq!(
        said(&found.lint),
        [(
            "cargo clippy --all-targets -- -D warnings",
            "Cargo.toml:2",
            Report::Nothing
        )]
    );
    assert!(found.e2e.is_empty() && found.e2e_tools.is_empty());
    assert_eq!(found.glossary.as_deref(), Some("GLOSSARY.md"));
    assert_eq!(found.adrs, ["docs/adr/0001-entries-are-append-only.md"]);
    assert!(open(&found).is_empty(), "{:?}", open(&found));

    let setup = recommended(&found);
    let names: Vec<&str> = setup
        .config
        .stages
        .execution
        .checks
        .iter()
        .map(|check| check.name.as_str())
        .collect();
    assert_eq!(names, ["unit", "lint"]);
    assert_eq!(setup.scripts[0].command, "cargo test");
    assert_eq!(setup.scripts[0].source.as_deref(), Some("Cargo.toml:2"));
    assert_eq!(setup.config.review.reviewers[0].agent, Agent::Claude);
    assert_eq!(config::parse(&setup.yaml), Ok(setup.config.clone()));
}

#[test]
fn a_node_project_runs_vitest_with_a_report_and_playwright_from_its_script() {
    let found = detected(&fixture("node"), machine());
    assert_eq!(
        said(&found.test),
        [(
            "pnpm exec vitest run --reporter=default --reporter=json --outputFile=\"$DEVFLOW_REPORT_DIR/tests.json\"",
            "package.json:6",
            Report::Vitest
        )]
    );
    assert_eq!(
        said(&found.e2e),
        [("pnpm run test:e2e", "package.json:7", Report::Nothing)]
    );
    assert_eq!(
        said(&found.lint),
        [("pnpm run lint", "package.json:8", Report::Nothing)]
    );
    assert_eq!(found.e2e_tools[0].name, "playwright");
    assert_eq!(found.e2e_tools[0].source, "playwright.config.ts");
    assert_eq!(found.glossary.as_deref(), Some("CONTEXT.md"));
    assert!(open(&found).is_empty(), "{:?}", open(&found));

    let setup = recommended(&found);
    let e2e = &setup.config.stages.execution.checks[1];
    assert_eq!(e2e.name, "e2e");
    assert_eq!(e2e.evidence, [Evidence::Screenshots, Evidence::Video]);
    assert_eq!(e2e.report, Report::Junit);
    assert_eq!(e2e.run, "sh .devflow/scripts/check-e2e.sh");
    let script = setup
        .scripts
        .iter()
        .find(|script| script.name == "e2e")
        .expect("the e2e script");
    assert_eq!(
        script.command,
        "pnpm exec playwright test --config .devflow/playwright.config.ts"
    );
    assert_eq!(script.source.as_deref(), Some("playwright.config.ts"));
    // The project's own E2E suite stays where it is, and is still called.
    let suite = &setup.config.stages.execution.checks[2];
    assert_eq!(suite.name, "e2e-suite");
    assert!(setup
        .scripts
        .iter()
        .any(|script| script.name == "e2e-suite" && script.command == "pnpm run test:e2e"));
}

#[test]
fn a_playwright_project_gets_a_config_for_devflows_specs_with_their_evidence() {
    let root = tempfile::tempdir().expect("tempdir");
    let setup = recommended(&detected(&fixture("node"), machine()));
    let done = devflow_engine::setup::write(root.path(), &setup.files).expect("written");
    assert!(done
        .iter()
        .any(|one| one.path == ".devflow/playwright.config.ts" && one.change == "create"));
    let written = std::fs::read_to_string(root.path().join(".devflow/playwright.config.ts"))
        .expect("the config");
    for said in [
        "import base from '../../playwright.config'",
        "testDir: `${root}/.devflow/e2e`",
        "['junit', { outputFile: `${reports}/report.xml` }]",
        "process.env.DEVFLOW_REPORT_DIR",
        "screenshot: 'on', video: 'on'",
    ] {
        assert!(written.contains(said), "{said} in:\n{written}");
    }

    // Without Playwright there is no config to write.
    let php = recommended(&detected(&fixture("php"), machine()));
    assert!(php
        .files
        .iter()
        .all(|file| file.path != ".devflow/playwright.config.ts"));
}

#[test]
fn a_php_project_runs_phpunit_with_junit_and_asks_about_cypress() {
    let found = detected(&fixture("php"), machine());
    assert_eq!(
        said(&found.test),
        [(
            "vendor/bin/phpunit --log-junit \"$DEVFLOW_REPORT_DIR/phpunit.xml\"",
            "composer.json:9",
            Report::Junit
        )]
    );
    assert_eq!(
        said(&found.lint),
        [(
            "vendor/bin/phpstan analyse",
            "composer.json:8",
            Report::Nothing
        )]
    );
    assert_eq!(found.e2e_tools[0].name, "cypress");
    assert_eq!(
        found.adrs,
        [
            "docs/adr/0001-invoices-are-numbered-per-year.md",
            "docs/adr/0002-amounts-are-cents.md"
        ]
    );
    assert_eq!(found.glossary, None);
    assert_eq!(
        open(&found),
        ["cypress is set up (cypress.config.js), but no command in the repo runs it"]
    );

    let setup = recommended(&found);
    assert_eq!(
        setup.config.stages.execution.checks[0].report,
        Report::Junit
    );
    assert!(!setup.config.decisions.use_);
}
