use super::*;
use crate::config::{Check, Report};
use crate::detect::{Detected, E2eTool};

fn detected(tools: Vec<E2eTool>) -> Detected {
    Detected {
        test: vec![],
        e2e: vec![],
        lint: vec![],
        typecheck: vec![],
        nested: vec![],
        e2e_tools: tools,
        clis: vec![],
        decisions_key: false,
        decisions_opted_out: false,
        glossary: None,
        adrs: vec![],
        hints: Default::default(),
    }
}

fn tool(name: &str, source: &str) -> E2eTool {
    E2eTool {
        name: name.into(),
        source: source.into(),
        run: None,
    }
}

#[test]
fn the_config_keeps_a_junit_report_screenshots_and_video_where_devpit_reads_them() {
    let text = text("tests/devflow", None);
    for said in [
        "testDir: `${root}/tests/devflow`",
        "testMatch: '**/*.spec.ts'",
        "outputDir: `${reports}/test-results`",
        "['junit', { outputFile: `${reports}/report.xml` }]",
        "use: { screenshot: 'on', video: 'on' }",
        "const reports = process.env.DEVFLOW_REPORT_DIR ??",
    ] {
        assert!(text.contains(said), "{said} in:\n{text}");
    }
    assert!(
        !text.contains("import base") && !text.contains("...base"),
        "{text}"
    );
}

#[test]
fn the_projects_own_config_is_the_base_and_its_server_starts_from_the_root() {
    let text = text(".devflow/e2e", Some("playwright.config.ts"));
    assert!(
        text.contains("import base from '../../playwright.config'\n"),
        "{text}"
    );
    assert!(text.contains("  ...base,\n"), "{text}");
    assert!(
        text.contains("use: { ...base.use, screenshot: 'on', video: 'on' }"),
        "{text}"
    );
    assert!(text.contains("({ cwd: root, ...server })"), "{text}");
    // A module JavaScript cannot import without its extension keeps it.
    let mjs = super::text(".devflow/e2e", Some("playwright.config.mjs"));
    assert!(mjs.contains("from '../../playwright.config.mjs'"), "{mjs}");
}

#[test]
fn playwright_is_wanted_when_detected_or_when_a_check_runs_it() {
    let mut config = Config::default();
    assert!(!wanted(&config, &detected(vec![])));
    assert!(!wanted(
        &config,
        &detected(vec![tool("cypress", "cypress.config.ts")])
    ));
    assert!(wanted(
        &config,
        &detected(vec![tool("playwright", "package.json:9")])
    ));
    config.stages.execution.checks.push(Check {
        name: "e2e".into(),
        run: "npx playwright test".into(),
        report: Report::Junit,
        evidence: vec![],
        requires: None,
        exclusive: None,
    });
    assert!(wanted(&config, &detected(vec![])));
}

#[test]
fn only_a_config_file_is_a_base() {
    assert_eq!(
        base(&detected(vec![tool("playwright", "playwright.config.ts")])),
        Some("playwright.config.ts")
    );
    // Found in package.json: no config of the project's to import.
    assert_eq!(
        base(&detected(vec![tool("playwright", "package.json:9")])),
        None
    );
}
