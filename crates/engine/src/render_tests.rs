use std::collections::BTreeMap;

use super::*;
use crate::config::{parse, Agent, Check, Evidence, Mode, Report, Reviewer, Severity};

fn full() -> Config {
    let mut config = Config {
        enabled: true,
        ..Config::default()
    };
    config.stages.context.enabled = false;
    config.stages.plan.approve = crate::config::Approve::Nobody;
    config.stages.execution.checks = vec![
        Check {
            name: "unit".into(),
            run: "pnpm exec vitest run --reporter=json --outputFile=\"$DEVFLOW_REPORT_DIR/tests.json\""
                .into(),
            report: Report::Vitest,
            evidence: Vec::new(),
            requires: None,
            exclusive: None,
        },
        Check {
            name: "e2e".into(),
            run: "make e2e # not a comment: true".into(),
            report: Report::Junit,
            evidence: vec![Evidence::Screenshots, Evidence::Video],
            requires: None,
            exclusive: None,
        },
        Check {
            name: "lint".into(),
            run: "true".into(),
            report: Report::Nothing,
            evidence: Vec::new(),
            requires: Some("pg_isready -q".into()),
            exclusive: Some("postgres-test".into()),
        },
    ];
    config.stages.execution.e2e_dir = "tests/e2e".into();
    config.review.reviewers = vec![Reviewer {
        agent: Agent::Gemini,
        persona: "devflow-spec".into(),
        model: Some("pro: 2.5".into()),
    }];
    config.review.block_on = vec![Severity::Critical];
    config.review.consolidate = crate::config::Consolidate::Agent;
    config.review.scale = Some(crate::scale::Scale {
        small_lines: 40,
        sensitive: vec!["*.sql".into(), ".github/workflows/**".into()],
    });
    config.review.verify = crate::config::Verify::Required;
    config.decisions.use_ = true;
    config.decisions.mode = Mode::Enforce;
    config.decisions.rubrics = BTreeMap::from([("completion".into(), "devflow-done".into())]);
    config
}

#[test]
fn what_is_written_reads_back_the_same() {
    let mut scaled = Config::default();
    scaled.review.scale = Some(crate::scale::Scale::default());
    for config in [Config::default(), full(), scaled] {
        let text = render(&config);
        assert_eq!(parse(&text), Ok(config), "{text}");
    }
}

#[test]
fn the_file_says_who_switches_it_on() {
    let text = render(&Config::default());
    assert!(text.starts_with("# Devflow"), "{text}");
    assert!(
        text.contains("never by an agent.\nenabled: false\n"),
        "{text}"
    );
}

#[test]
fn a_string_that_would_read_as_something_else_is_quoted() {
    assert_eq!(scalar("make test"), "make test");
    assert_eq!(scalar(".devflow/e2e"), ".devflow/e2e");
    for typed in ["true", "no", "1.5", "~", "a: b", "a #b", "-x", "", "\"q\""] {
        assert!(scalar(typed).starts_with('"'), "{typed}");
    }
    assert_eq!(scalar("say \"hi\"\n"), r#""say \"hi\"\n""#);
}

#[test]
fn where_the_specs_go_is_written_only_when_it_was_moved() {
    let v1 = parse("version: 1\n").expect("a version 1 file");
    for mut config in [Config::default(), full(), v1] {
        config.stages.execution.e2e_dir = crate::config::E2E_DIR.into();
        let text = render(&config);
        assert!(!text.contains("e2e_dir"), "{text}");
        config.stages.execution.e2e_dir = "tests/e2e".into();
        let moved = render(&config);
        assert!(moved.contains("    e2e_dir: tests/e2e\n"), "{moved}");
        assert_eq!(parse(&moved), Ok(config));
    }
}
