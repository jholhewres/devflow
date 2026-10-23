use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use serde_json::json;

use super::*;
use crate::config::{Evidence as Kept, Report as Format};

const EXECUTION: &str = include_str!("../../../flow/skills/devflow-execution/SKILL.md");
const COMPLETION: &str = include_str!("../../../flow/skills/devflow-completion/SKILL.md");

/// The JSON blocks of a skill that call the evidence tool, as the engine
/// reads them: the tool's `item` is the engine's `card`.
fn sent(skill: &str) -> Vec<Value> {
    skill
        .split("```json")
        .skip(1)
        .filter_map(|rest| rest.split("```").next())
        .filter_map(|block| serde_json::from_str::<Value>(block).ok())
        .filter(|value| value.get("item").is_some() && value.get("criteria").is_some())
        .map(|mut value| {
            let item = value["item"].take();
            let fields = value.as_object_mut().expect("an object");
            fields.remove("item");
            fields.insert("card".to_owned(), item);
            value
        })
        .collect()
}

#[test]
fn the_evidence_takes_exactly_what_the_skills_send() {
    let execution = sent(EXECUTION);
    let completion = sent(COMPLETION);
    assert_eq!((execution.len(), completion.len()), (1, 1));
    let full = asked(&execution[0]).expect("the execution skill's call");
    assert_eq!(full.card, "<item id>");
    assert_eq!(
        full.checks.as_deref(),
        Some(&["<check name from devflow.yaml>".to_owned()][..])
    );
    assert_eq!(full.criteria[0].tests.len(), 1);
    assert_eq!(full.red[0].test, full.criteria[0].tests[0]);
    let fresh = asked(&completion[0]).expect("the completion skill's call");
    assert_eq!(fresh.checks, None);
    assert!(fresh.red.is_empty());
}

#[test]
fn anything_but_that_shape_is_refused_with_the_shape() {
    let refused = asked(&json!({ "card": "card_1", "criterias": [] })).expect_err("a typo");
    assert!(
        refused.contains("`criterias`") && refused.contains(SHAPE),
        "{refused}"
    );
    let nested = json!({ "card": "card_1", "criteria": [{ "criterion": "a", "test": "b" }] });
    assert!(asked(&nested).is_err());
    assert!(asked(&json!({ "card": " " })).is_err());
    assert!(asked(&json!({ "checks": [] })).is_err());
    let long =
        json!({ "card": "card_1", "red": [{ "test": "t", "failure": "x".repeat(LONGEST + 1) }] });
    assert!(asked(&long).is_err());
    // An orchestrator names the project, as on every board tool.
    assert!(asked(&json!({ "card": "card_1", "project": "devflow" })).is_ok());
}

fn check(name: &str, run: &str) -> Check {
    Check {
        name: name.into(),
        run: run.into(),
        report: Format::Junit,
        evidence: Vec::new(),
        requires: None,
        exclusive: None,
    }
}

fn config(checks: Vec<Check>) -> Config {
    let mut config = Config::default();
    config.stages.execution.checks = checks;
    config
}

#[test]
fn every_check_runs_unless_some_are_named_and_a_name_not_configured_is_refused() {
    let checks = [
        check("unit", "true"),
        check("e2e", "true"),
        check("lint", "true"),
    ];
    let names = |chosen: Vec<&Check>| -> Vec<String> {
        chosen.iter().map(|check| check.name.clone()).collect()
    };
    assert_eq!(
        names(chosen(&checks, None).expect("all")),
        ["unit", "e2e", "lint"]
    );
    let named = ["lint".to_owned(), "unit".to_owned()];
    assert_eq!(
        names(chosen(&checks, Some(&named)).expect("two")),
        ["unit", "lint"]
    );
    let unknown = chosen(&checks, Some(&["typo".to_owned()])).expect_err("unknown");
    assert!(unknown.contains("unit, e2e, lint"), "{unknown}");
    assert!(chosen(&[], None).is_err());
}

/// A proof counts only when its file is there, in the run's folder or the
/// checkout, and never outside them; a criterion naming neither a test nor
/// a proof proves nothing.
#[test]
fn a_criterion_is_proved_by_a_file_that_is_there_and_not_by_one_that_is_not() {
    let base = tempfile::tempdir().expect("base");
    let root = base.path().join("checkout");
    std::fs::create_dir_all(root.join("shots")).expect("shots");
    std::fs::write(root.join("shots/dialog.png"), "png").expect("a screenshot");
    std::fs::write(base.path().join("outside.png"), "png").expect("outside");
    let config = config(vec![check(
        "unit",
        &format!(r#"{PASSING}; printf png > "$DEVFLOW_REPORT_DIR/shot.png""#),
    )]);
    let proof = |kind: &str, path: &str| json!({ "kind": kind, "path": path });
    let asked = asked(&json!({ "card": "card_1", "criteria": [
        { "criterion": "rename changes the title", "proof": proof("screenshot", "shots/dialog.png") },
        { "criterion": "an empty title is refused", "proof": proof("e2e", "unit/shot.png") },
        { "criterion": "the old title is kept in history", "proof": proof("screenshot", "shots/missing.png") },
        { "criterion": "outside", "proof": proof("artifact", "../outside.png") },
        { "criterion": "neither" },
    ] }))
    .expect("asked");
    let evidence = run_of(&root, &config, &asked, "Rename", 0);
    let green: Vec<bool> = evidence.criteria.iter().map(Seen::green).collect();
    assert_eq!(green, [true, true, false, false, false]);
    let record = recorded(&evidence);
    assert_eq!(
        record["criteria"][0]["proof"],
        json!({ "kind": "screenshot", "path": "shots/dialog.png", "exists": true })
    );
    assert_eq!(record["criteria"][2]["proof"]["exists"], false);
}

/// A JUnit report the check writes, as a test runner would.
const PASSING: &str = r#"printf '<testsuite><testcase classname="cli" name="rename changes the title"/><testcase classname="cli" name="an empty title is refused"/></testsuite>' > "$DEVFLOW_REPORT_DIR/report.xml""#;
const FAILING: &str = r#"printf '<testsuite><testcase classname="cli" name="rename changes the title"/><testcase classname="cli" name="an empty title is refused"><failure message="expected an error"/></testcase></testsuite>' > "$DEVFLOW_REPORT_DIR/report.xml"; echo the last words; exit 1"#;

/// devpit's folder for the runs of a checkout at `root`, beside it in a test.
fn runs_of(root: &Path) -> runs::Runs {
    runs::Runs {
        home: root.join("devpit-home"),
        checkout: root.to_path_buf(),
    }
}

fn run_of(root: &Path, config: &Config, asked: &Asked, title: &str, seconds: u64) -> Evidence {
    let context = Context {
        item: "card_1".into(),
        item_title: title.into(),
        ..Context::default()
    };
    let body = "## Acceptance criteria\n- [ ] rename changes the title\n- [ ] an empty title is refused\n- [ ] the old title is kept in history\n";
    gathered(&Given {
        root,
        runs: &runs_of(root),
        locks: &root.join("devpit-home").join("locks"),
        config,
        asked,
        card: Card {
            id: "card_1",
            title,
            body,
        },
        context: &context,
        budget: Duration::from_secs(60),
        redact: &|text: &str| text.replace("s3cr3t-token", "[hidden]"),
        at: UNIX_EPOCH + Duration::from_secs(1_791_729_005 + seconds),
    })
    .expect("a run")
}

fn nothing_asked() -> Asked {
    asked(&json!({ "card": "card_1" })).expect("asked")
}

#[test]
fn a_check_gets_the_card_only_through_its_environment() {
    let root = tempfile::tempdir().expect("root");
    let title = "x; touch pwned $(touch pwned2)";
    let config = config(vec![check(
        "unit",
        r#"printf '%s' "$DEVFLOW_ITEM_TITLE" > "$DEVFLOW_REPORT_DIR/title.txt"; printf '%s' "$DEVFLOW_ITEM" > "$DEVFLOW_REPORT_DIR/card.txt""#,
    )]);
    let evidence = run_of(root.path(), &config, &nothing_asked(), title, 0);
    let folder = root.path().join(&evidence.folder).join("unit");
    assert_eq!(
        std::fs::read_to_string(folder.join("title.txt")).expect("title"),
        title
    );
    assert_eq!(
        std::fs::read_to_string(folder.join("card.txt")).expect("card"),
        "card_1"
    );
    assert!(!root.path().join("pwned").exists() && !root.path().join("pwned2").exists());
}

#[test]
fn a_green_run_with_a_report_is_green_and_one_without_a_report_is_not() {
    let root = tempfile::tempdir().expect("root");
    let config = config(vec![check("unit", PASSING), check("lint", "echo fine")]);
    let evidence = run_of(root.path(), &config, &nothing_asked(), "Rename", 0);
    let verdicts: Vec<Verdict> = evidence.checks.iter().map(|ran| ran.verdict).collect();
    // A check set to write a report that wrote none proves nothing: a command step's rule.
    assert_eq!(verdicts, [Verdict::Passed, Verdict::Inconclusive]);
    assert!(!evidence.green());

    let unit_only = asked(&json!({ "card": "card_1", "checks": ["unit"] })).expect("asked");
    let evidence = run_of(root.path(), &config, &unit_only, "Rename", 1);
    assert!(evidence.green());
    let summary = summary(&evidence, &Attached::default(), "devflow/card_1/x");
    assert_eq!(summary["green"], true);
    assert_eq!(summary["checks"][0]["result"], "passed");
    assert_eq!(summary["checks"][0]["tests"]["passed"], 2);
}

/// A check that writes no report: a Makefile target, a linter.
fn bare(name: &str, run: &str) -> Check {
    Check {
        report: Format::Nothing,
        ..check(name, run)
    }
}

#[test]
fn a_check_set_to_no_report_is_judged_by_its_exit_code() {
    let root = tempfile::tempdir().expect("root");
    let config = config(vec![
        bare("lint", "echo fine"),
        bare("vet", "echo broken; exit 1"),
        bare("go", "devpit-no-such-command-anywhere ./..."),
    ]);
    let evidence = run_of(root.path(), &config, &nothing_asked(), "Rename", 0);
    let verdicts: Vec<Verdict> = evidence.checks.iter().map(|ran| ran.verdict).collect();
    assert_eq!(
        verdicts,
        [Verdict::Passed, Verdict::Failed, Verdict::NotRun]
    );
    let missing = evidence.checks[2].not_run.as_deref().unwrap_or_default();
    assert!(missing.contains("no such command"), "{missing}");

    let lint_only = asked(&json!({ "card": "card_1", "checks": ["lint"] })).expect("asked");
    let evidence = run_of(root.path(), &config, &lint_only, "Rename", 1);
    assert!(evidence.green());
    let said = comment(&evidence, &[]);
    assert!(
        said.contains("- lint: passed, exit 0, no report devflow reads\n"),
        "{said}"
    );
}

#[test]
fn a_check_set_to_a_report_keeps_a_command_steps_rule() {
    let ok = |format| checked(format, RunState::Ok, None, Some(0));
    let missing = |format| checked(format, RunState::Failed, None, Some(127));
    for format in [Format::Junit, Format::Cargo, Format::Vitest, Format::Jest] {
        assert_eq!(ok(format), Verdict::Inconclusive, "{format:?}");
        assert_eq!(missing(format), Verdict::Inconclusive, "{format:?}");
        let none_ran = Some(Report {
            passed: 0,
            failed: 0,
        });
        assert_eq!(
            checked(format, RunState::Ok, none_ran, Some(0)),
            Verdict::Inconclusive
        );
    }
    // A report that names a failure fails a check whatever it was set to write.
    let red = Some(Report {
        passed: 3,
        failed: 1,
    });
    assert_eq!(
        checked(Format::Nothing, RunState::Ok, red, Some(0)),
        Verdict::Failed
    );
    assert_eq!(
        checked(Format::Nothing, RunState::Failed, None, None),
        Verdict::Failed
    );
}

#[test]
fn the_report_leads_to_a_short_summary_with_the_counts_the_failures_and_the_paths() {
    let root = tempfile::tempdir().expect("root");
    let config = config(vec![check("unit", FAILING)]);
    let asked = asked(&json!({
        "card": "card_1",
        "criteria": [
            { "criterion": "rename changes the title", "tests": ["cli.rename changes the title"] },
            { "criterion": "an empty title is refused", "tests": ["an empty title is refused"] },
            { "criterion": "something the card never said", "tests": ["nowhere"] }
        ],
        "red": [{ "test": "rename changes the title", "failure": "expected 'b', got 'a' with s3cr3t-token" }]
    }))
    .expect("asked");
    let evidence = run_of(root.path(), &config, &asked, "[devflow] Rename a card", 0);
    let said = summary(
        &evidence,
        &Attached::default(),
        "devflow/card_1/20261011T143005Z",
    );

    assert_eq!(said["green"], false);
    let unit = &said["checks"][0];
    assert_eq!(unit["result"], "failed");
    assert_eq!(unit["exit"], 1);
    assert_eq!(
        (
            unit["tests"]["passed"].clone(),
            unit["tests"]["failed"].clone()
        ),
        (json!(1), json!(1))
    );
    assert_eq!(unit["failures"][0]["name"], "an empty title is refused");
    assert_eq!(unit["failures"][0]["message"], "expected an error");
    assert_eq!(unit["last_lines"], json!(["the last words"]));
    let run = runs_of(&root.path().canonicalize().expect("real"))
        .home
        .join("card_1/20261011T143005Z")
        .display()
        .to_string();
    assert_eq!(said["run"], run);
    assert!(
        !root.path().join(runs::RUNS).exists(),
        "a run in the checkout"
    );
    assert_eq!(unit["reports"], json!([format!("{run}/unit/report.xml")]));
    assert_eq!(unit["log"], format!("{run}/unit.log"));
    assert!(said.to_string().len() < 4096, "short: {said}");

    let results: Vec<(&str, bool, bool)> = evidence
        .criteria
        .iter()
        .map(|seen| (seen.criterion.as_str(), seen.on_card, seen.green()))
        .collect();
    assert_eq!(
        results,
        [
            ("rename changes the title", true, true),
            ("an empty title is refused", true, false),
            ("something the card never said", false, false)
        ]
    );
    assert_eq!(said["criteria_green"], "1 of 3");
    assert_eq!(
        said["not_mapped"],
        json!(["the old title is kept in history"])
    );
    assert_eq!(said["red_now_green"], "1 of 1");
    assert_eq!(
        evidence.red[0].failure,
        "expected 'b', got 'a' with [hidden]"
    );

    let kept: Value = serde_json::from_str(
        &std::fs::read_to_string(root.path().join(run).join("evidence.json")).expect("kept"),
    )
    .expect("json");
    assert_eq!(kept["red"][0]["now"], "passed");
    assert_eq!(kept["devflow"]["version"], env!("CARGO_PKG_VERSION"));
    assert!(kept["devflow"]["skills"]["devflow-execution"]
        .as_str()
        .is_some_and(|digest| digest.starts_with("sha256:")));
    assert_eq!(kept["criteria"][2]["tests"][0]["result"], "not found");
    assert!(evidence.spec.is_none(), "no e2e check, no spec");
}

#[test]
fn what_devpit_knows_to_be_secret_leaves_the_report_and_the_log() {
    let root = tempfile::tempdir().expect("root");
    let config = config(vec![check(
        "unit",
        r#"echo token s3cr3t-token; printf '<testsuite><testcase name="leaks"><failure message="got s3cr3t-token"/></testcase></testsuite>' > "$DEVFLOW_REPORT_DIR/report.xml"; exit 1"#,
    )]);
    let evidence = run_of(root.path(), &config, &nothing_asked(), "Leak", 0);
    let run = root.path().join(&evidence.folder);
    for file in ["unit/report.xml", "unit.log"] {
        let text = std::fs::read_to_string(run.join(file)).expect("kept");
        assert!(
            !text.contains("s3cr3t-token") && text.contains("[hidden]"),
            "{file}: {text}"
        );
    }
    let failures = &evidence.checks[0]
        .reported
        .as_ref()
        .expect("a report")
        .tested
        .failures;
    assert_eq!(failures[0].message.as_deref(), Some("got [hidden]"));
}

#[test]
fn a_card_keeps_only_its_newest_runs() {
    let root = tempfile::tempdir().expect("root");
    let config = config(vec![check("unit", PASSING)]);
    let mut pruned = Vec::new();
    for second in 0..(runs::KEPT as u64 + 2) {
        pruned.extend(run_of(root.path(), &config, &nothing_asked(), "Rename", second).pruned);
    }
    assert_eq!(pruned, ["20261011T143005Z", "20261011T143006Z"]);
    let left = std::fs::read_dir(runs_of(root.path()).home.join("card_1"))
        .expect("runs")
        .count();
    assert_eq!(left, runs::KEPT);
}

#[test]
fn the_e2e_spec_is_named_after_the_card() {
    assert_eq!(
        spec_path(
            ".devflow/e2e",
            "card_01",
            "[devflow] Rename changes the title!"
        ),
        ".devflow/e2e/card_01-rename-changes-the-title.spec.ts"
    );
    assert_eq!(spec_path("e2e", "card_01", "¿¿"), "e2e/card_01.spec.ts");
    let root = tempfile::tempdir().expect("root");
    let mut config = config(vec![check("e2e", PASSING)]);
    config.stages.execution.e2e_dir = "tests/devflow".into();
    let evidence = run_of(
        root.path(),
        &config,
        &nothing_asked(),
        "[devflow] Rename",
        0,
    );
    assert_eq!(
        evidence.spec,
        Some(Spec {
            path: "tests/devflow/card_1-rename.spec.ts".into(),
            exists: false
        })
    );
}

#[test]
fn the_cards_comment_says_each_check_and_links_what_was_attached() {
    let root = tempfile::tempdir().expect("root");
    let mut e2e = check(
        "e2e",
        r#"mkdir -p "$DEVFLOW_REPORT_DIR/test-results/a" && printf png > "$DEVFLOW_REPORT_DIR/test-results/a/shot.png" && printf '<testsuite><testcase name="renames"/></testsuite>' > "$DEVFLOW_REPORT_DIR/report.xml""#,
    );
    e2e.evidence = vec![Kept::Screenshots];
    let config = config(vec![check("unit", FAILING), e2e]);
    let evidence = run_of(root.path(), &config, &nothing_asked(), "Rename", 0);
    let run = root.path().join(&evidence.folder);
    let files = evidence.files(&run);
    assert_eq!(
        files,
        [
            "unit/report.xml",
            "unit.log",
            "e2e/report.xml",
            "e2e.log",
            "screenshots/e2e-test-results-a-shot.png",
            "evidence.json"
        ]
    );
    let links: Vec<(String, String)> = files
        .iter()
        .map(|file| (file.clone(), format!("/artifacts/devflow/card_1/x/{file}")))
        .collect();
    let said = comment(&evidence, &links);
    assert!(
        said.starts_with("[devflow] evidence: 1 of 2 checks green, run 20261011T143005Z\n"),
        "{said}"
    );
    assert!(
        said.contains("- unit: failed, 1 passed, 1 failed\n"),
        "{said}"
    );
    assert!(said.contains("- e2e: passed, 1 passed\n"), "{said}");
    assert!(
        said.contains("[screenshots/e2e-test-results-a-shot.png](/artifacts/devflow/card_1/x/screenshots/e2e-test-results-a-shot.png)"),
        "{said}"
    );
}

#[test]
fn a_check_whose_prerequisite_fails_is_not_run_rather_than_red() {
    let root = tempfile::tempdir().expect("root");
    let needs = |requires: &str| Check {
        requires: Some(requires.into()),
        ..bare("db", "touch ran; exit 1")
    };
    let failing = config(vec![needs("exit 2")]);
    let evidence = run_of(root.path(), &failing, &nothing_asked(), "Rename", 0);
    assert_eq!(evidence.checks[0].verdict, Verdict::NotRun);
    let why = evidence.checks[0].not_run.as_deref().expect("why");
    assert!(why.starts_with("prerequisite failed: `exit 2`"), "{why}");
    assert!(!root.path().join("ran").exists());

    let passing = config(vec![needs("true")]);
    let evidence = run_of(root.path(), &passing, &nothing_asked(), "Rename", 1);
    assert_eq!(evidence.checks[0].verdict, Verdict::Failed);
    assert!(root.path().join("ran").exists());
}

/// Two cards' checks on one test database: each appends its start and end,
/// and a lock that holds never lets the other's start fall in between.
#[test]
fn two_checks_with_the_same_exclusive_never_overlap() {
    let root = tempfile::tempdir().expect("root");
    let locks = root.path().join("locks");
    let exclusive = |name: &str| Check {
        exclusive: Some("postgres-test".into()),
        ..bare(
            name,
            &format!(
                "echo {name}-start >> markers; sleep 0.5; echo {name}-end >> markers; \
                 test -n \"$DEVFLOW_LOCK_POSTGRES_TEST\""
            ),
        )
    };
    let ran: Vec<Ran> = std::thread::scope(|scope| {
        let runs: Vec<_> = ["a", "b"]
            .into_iter()
            .map(|name| {
                let (root, locks, check) = (root.path(), &locks, exclusive(name));
                scope.spawn(move || {
                    let run = root.join(format!("run-{}", check.name));
                    std::fs::create_dir_all(&run).expect("run");
                    run_check(
                        &check,
                        root,
                        &run,
                        locks,
                        &Context::default(),
                        Duration::from_secs(30),
                        &|text: &str| text.to_owned(),
                    )
                })
            })
            .collect();
        runs.into_iter()
            .map(|one| one.join().expect("ran"))
            .collect()
    });
    assert!(
        ran.iter().all(|one| one.verdict == Verdict::Passed),
        "{ran:?}"
    );
    let markers = std::fs::read_to_string(root.path().join("markers")).expect("markers");
    let lines: Vec<&str> = markers.lines().collect();
    assert_eq!(lines.len(), 4, "{markers}");
    for pair in lines.chunks(2) {
        let name = pair[0].strip_suffix("-start").expect("a start");
        assert_eq!(pair[1], format!("{name}-end"), "{markers}");
    }
}
