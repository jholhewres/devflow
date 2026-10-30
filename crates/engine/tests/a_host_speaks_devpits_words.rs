//! With devpit's dialect and devpit's own `flow/`, the engine says what
//! devpit's own copy of it says, byte for byte.
//!
//! The goldens in `fixtures/devpit-golden/` were written once by a throwaway
//! harness, `~/jhol/scripts/devpit/d0b/harness/` (its own Cargo workspace,
//! never versioned), that depends on devpit's `crates/devflow` by path and
//! prints what it says for the inputs below, at devpit commit
//! 4f8c6ab84b1ad08fd0b29bf1ab8f7e6519b63177. `fixtures/devpit-flow/` is that
//! commit's `flow/`, the files the engine embeds. Every input here mirrors the
//! harness's: change one, change both and write the goldens again.
//!
//! devpit's build sorts JSON keys; this one keeps them in the order written
//! (`preserve_order`). JSON is compared after sorting its keys, which is the
//! one difference that is not words.

use std::path::Path;
use std::sync::Once;
use std::time::{Duration, SystemTime};

use devflow_engine as b;
use devflow_engine::dialect::{Assets, Tools};
use devflow_engine::Dialect;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

macro_rules! flow {
    ($path:literal) => {
        include_str!(concat!("fixtures/devpit-flow/", $path))
    };
}

static DEVPIT_FLOW: Assets = Assets {
    skills: [
        (
            "devflow-briefing",
            Some("briefing"),
            flow!("skills/devflow-briefing/SKILL.md"),
        ),
        (
            "devflow-context",
            Some("context"),
            flow!("skills/devflow-context/SKILL.md"),
        ),
        (
            "devflow-plan",
            Some("plan"),
            flow!("skills/devflow-plan/SKILL.md"),
        ),
        (
            "devflow-execution",
            Some("execution"),
            flow!("skills/devflow-execution/SKILL.md"),
        ),
        (
            "devflow-review",
            Some("review"),
            flow!("skills/devflow-review/SKILL.md"),
        ),
        (
            "devflow-completion",
            Some("completion"),
            flow!("skills/devflow-completion/SKILL.md"),
        ),
        (
            "devflow-setup",
            None,
            flow!("skills/devflow-setup/SKILL.md"),
        ),
    ],
    personas: [
        ("devflow-spec", flow!("personas/devflow-spec.md")),
        ("devflow-standards", flow!("personas/devflow-standards.md")),
        ("devflow-security", flow!("personas/devflow-security.md")),
        ("devflow-all", flow!("personas/devflow-all.md")),
    ],
    rubrics: [
        ("devflow-finding", flow!("rubrics/devflow-finding.json")),
        ("devflow-brief", flow!("rubrics/devflow-brief.json")),
        ("devflow-plan", flow!("rubrics/devflow-plan.json")),
    ],
    schema: flow!("schemas/devflow-findings.schema.json"),
    publish: [
        flow!("publish/github.md"),
        flow!("publish/gitlab.md"),
        flow!("publish/bitbucket.md"),
    ],
};

/// devpit's words, as D1 will pass them.
static DEVPIT: Dialect = Dialect {
    product: "devpit",
    version: "0.1.45",
    env: "DEVPIT",
    folder: ".devpit/devflow",
    item: "card",
    items: "cards",
    an_item: "a card",
    work_item: "card",
    a_work_item: "a card",
    item_field: "card",
    tools: Tools {
        evidence: "devpit_devflow_evidence",
        gate: "devpit_devflow_gate",
        set: "devpit_devflow_set",
        stage: "devpit_devflow_stage",
        review: "devpit_devflow_review",
        publish: "devpit_devflow_publish",
        handoff: "devpit_handoff",
        finish: "devpit_finish_card",
    },
    files_label: "Attached",
    files_more: "among the artifacts",
    packet_heading: "Card",
    plan_board: "cards are made on the devpit board.",
    plan_outside: "is not another card of this plan, nor a card on the board (`card_…` or `#42`)",
    yaml_header: "# Devflow: briefing → context → plan → execution → review → completion,\n\
                  # served by devpit's MCP. This file is the source of truth: devpit edits\n\
                  # it and never commits it.\n",
    yaml_enabled: "# Switched on by the person's click in the devpit app, never by an agent.\n",
    yaml_enforce: "waits for the person's click in the app",
    yaml_provider: "the provider in Settings → Decisions",
    decisions_opted_out: "this project's state is not sent to Decisions — see Settings → Decisions",
    decisions_no_key: "no key — set one in Settings → Decisions",
    assets: &DEVPIT_FLOW,
};

/// devpit pins its folder once, before the first read; so does this process.
fn pinned() {
    static PIN: Once = Once::new();
    PIN.call_once(|| b::folder::pin(b::folder::LEGACY).expect("pinned"));
}

fn golden(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/devpit-golden")
        .join(format!("{name}.txt"));
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("{}", path.display()))
}

#[track_caller]
fn same(name: &str, said: &str) {
    let want = golden(name);
    assert!(
        said == want,
        "{name} differs from devpit's\n--- devpit\n{want}\n--- engine\n{said}"
    );
}

/// Keys sorted, as devpit's serde_json writes them.
fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(fields) => {
            let mut keys: Vec<&String> = fields.keys().collect();
            keys.sort();
            Value::Object(
                keys.into_iter()
                    .map(|key| (key.clone(), sorted(&fields[key])))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(&sorted(value)).expect("json")
}

fn pretty_text(text: &str) -> String {
    pretty(&serde_json::from_str(text).expect("json"))
}

fn err<T: std::fmt::Debug>(said: Result<T, String>) -> String {
    said.expect_err("refused")
}

const T0: u64 = 1_792_000_000;

fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(T0 + secs)
}

fn gate_config(review: bool) -> b::Config {
    b::config::parse_in(&DEVPIT, &format!(
        "version: 2\nstages:\n  - uses: builtin/execution\n    checks:\n      - {{ name: unit, run: make test, report: junit }}\n      - {{ name: e2e, run: make e2e, report: junit, evidence: [screenshots] }}\n  - uses: builtin/review\n    enabled: {review}\n  - uses: project/pr\n    gate: {{ command: \"./pr.sh\" }}\n"
    ))
    .expect("config")
}

#[test]
fn the_gate_says_what_is_missing_in_devpits_words() {
    pinned();
    use b::gate::{answer, checked, comment, Gate, Looked, Review, Run};
    let config = gate_config(true);
    let criteria = vec![
        "rename changes the title".to_owned(),
        "an empty title is refused".to_owned(),
    ];
    let none = checked(&Looked {
        dialect: &DEVPIT,
        config: &config,
        card: "card_1",
        criteria: &criteria,
        run: None,
        review: None,
        changed: None,
        stages: &[("pr".to_owned(), None)],
        unreviewed: None,
        no_code: false,
    });
    let gate = Gate::new(none, None, "20261011T120500Z");
    same("gate-missing-reason", &gate.reason());
    same(
        "gate-missing-answer",
        &pretty(&answer(&gate, Some("gate.json"))),
    );
    same("gate-missing-comment", &comment(&gate));

    let run = json!({
        "checks": [
            { "name": "unit", "result": "inconclusive", "screenshots": [] },
        ],
        "criteria": [
            { "criterion": "rename changes the title", "green": false,
              "tests": [{ "test": "rename", "result": "failed" }] },
        ],
        "spec": { "path": ".devpit/devflow/e2e/card_1-rename.spec.ts", "exists": true },
    });
    let findings =
        json!({ "verdict": "request_changes", "findings": [], "pending": ["devflow-spec"] });
    let stages = [(
        "pr".to_owned(),
        Some(("20261011T110000Z".to_owned(), json!({ "passed": false }))),
    )];
    let short = checked(&Looked {
        dialect: &DEVPIT,
        config: &config,
        card: "card_1",
        criteria: &criteria,
        run: Some(Run {
            name: "20261011T120000Z",
            evidence: &run,
        }),
        review: Some(Review {
            at: "20261011T120100Z",
            findings: &findings,
        }),
        changed: Some("20261011T120200Z"),
        stages: &stages,
        unreviewed: None,
        no_code: false,
    });
    let gate = Gate::new(short, None, "20261011T120500Z");
    same("gate-short-answer", &pretty(&answer(&gate, None)));
    same("gate-short-comment", &comment(&gate));

    let bare =
        b::config::parse("version: 2\nstages:\n  - uses: builtin/execution\n").expect("bare");
    let passed = checked(&Looked {
        dialect: &DEVPIT,
        config: &bare,
        card: "card_1",
        criteria: &[],
        run: Some(Run {
            name: "20261011T120000Z",
            evidence: &json!({ "checks": [] }),
        }),
        review: None,
        changed: None,
        stages: &[],
        unreviewed: None,
        no_code: false,
    });
    same("gate-nochecks-missing", &passed.missing.join("\n"));
    let mut ok = passed;
    ok.missing.clear();
    let gate = Gate::new(ok, None, "20261011T120500Z");
    same(
        "gate-passed-answer",
        &pretty(&answer(&gate, Some("gate.json"))),
    );

    same(
        "gate-asked-errors",
        &[
            err(b::gate::asked_in(&DEVPIT, &json!({ "cardd": "x" }))),
            err(b::gate::asked_in(&DEVPIT, &json!({}))),
            err(b::gate::asked_in(&DEVPIT, &json!([]))),
        ]
        .join("\n"),
    );
}

fn evidence_of(folder: &str) -> b::evidence::Evidence {
    use b::evidence::{Evidence, Proof, ProofKind, Ran, RedSeen, Seen, Spec};
    use b::runner::report::Outcome;
    use b::verdict::Verdict;
    let ran = |name: &str, verdict: Verdict, exit: Option<i32>| Ran {
        name: name.to_owned(),
        verdict,
        exit_code: exit,
        timed_out: false,
        seconds: 1.5,
        reported: None,
        log: Some(format!("{name}.log")),
        reports: Vec::new(),
        media: Default::default(),
        tail: vec!["last line".to_owned()],
        not_run: None,
    };
    Evidence {
        dialect: &DEVPIT,
        card: "card_1".to_owned(),
        stamp: "20261011T120000Z".to_owned(),
        folder: folder.to_owned(),
        checks: vec![
            ran("unit", Verdict::Inconclusive, Some(0)),
            ran("lint", Verdict::Inconclusive, None),
        ],
        criteria: vec![Seen {
            criterion: "rename changes the title".to_owned(),
            on_card: true,
            tests: vec![("rename".to_owned(), Some(Outcome::Passed))],
            proof: Some((
                Proof {
                    kind: ProofKind::Screenshot,
                    path: "shot.png".to_owned(),
                },
                false,
            )),
        }],
        not_mapped: vec!["an empty title is refused".to_owned()],
        red: vec![RedSeen {
            test: "rename".to_owned(),
            failure: "expected x".to_owned(),
            now: Some(Outcome::Passed),
        }],
        spec: Some(Spec {
            path: "e2e/card_1.spec.ts".to_owned(),
            exists: false,
        }),
        pruned: Vec::new(),
    }
}

#[test]
fn the_evidence_is_commented_recorded_and_summed_up_as_devpit_does() {
    pinned();
    use b::evidence::{comment, recorded, summary};
    let evidence = evidence_of("/runs/card_1/20261011T120000Z");
    let links: Vec<(String, String)> = (0..22)
        .map(|at| (format!("f{at}.txt"), format!("devpit://artifact/f{at}.txt")))
        .collect();
    same("evidence-comment", &comment(&evidence, &links));
    same("evidence-recorded", &pretty(&recorded(&evidence)));
    same(
        "evidence-summary",
        &pretty(&summary(
            &evidence,
            &Default::default(),
            "devflow/card_1/20261011T120000Z",
        )),
    );
    let config = gate_config(true);
    same(
        "evidence-errors",
        &[
            err(b::evidence::asked_in(&DEVPIT, &json!({ "card": " " }))),
            err(b::evidence::asked_in(
                &DEVPIT,
                &json!({ "card": "card_1", "nope": 1 }),
            )),
            err(b::evidence::chosen_in(&DEVPIT, &[], None)),
            err(b::evidence::chosen_in(
                &DEVPIT,
                &config.stages.execution.checks,
                Some(&["typo".to_owned()]),
            )),
        ]
        .join("\n"),
    );
}

const DIFF: &str = "diff --git a/src/a.rs b/src/a.rs\n--- a/src/a.rs\n+++ b/src/a.rs\n@@ -1,1 +1,2 @@\n fn a() {}\n+fn b() {}\n";

fn personas() -> b::review::Personas<'static> {
    b::review::Personas {
        dialect: &DEVPIT,
        personal: None,
        teams: &[],
    }
}

#[test]
fn a_review_hands_devpits_packet_prompt_and_variables() {
    pinned();
    use b::review::{env_of_in, packet, prompt, wide_in, Git, Packet};
    let files = vec!["src/a.rs".to_owned()];
    let git = Git {
        base: "b4se",
        head: "he4d",
        files: &files,
        diff: DIFF,
    };
    let criteria = vec!["rename changes the title".to_owned()];
    let text = packet(&Packet {
        dialect: &DEVPIT,
        card: b::evidence::Card {
            id: "card_1",
            title: "Rename",
            body: "",
        },
        git,
        criteria: &criteria,
        brief: None,
        standards: &[],
        evidence: None,
        previous: None,
        retro: false,
    });
    same("review-packet", &text);
    same(
        "review-prompt",
        &prompt("Persona text.", &text, "claude", "devflow-spec"),
    );
    let env = env_of_in(
        &DEVPIT,
        &[
            ("PATH".to_owned(), "/bin".to_owned()),
            ("DEVPIT_REVIEW_BASE".to_owned(), "stale".to_owned()),
            ("DEVFLOW_REVIEW_HEAD".to_owned(), "other".to_owned()),
        ],
        git,
        "/run/review-context.md",
        "devflow-spec",
    );
    same(
        "review-env",
        &env.iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    same("review-wide", &wide_in(&DEVPIT, 31, false).expect("wide"));
    same(
        "review-errors",
        &[
            err(b::review::asked_in(&DEVPIT, &json!({}))),
            err(b::review::asked_in(
                &DEVPIT,
                &json!({ "card": "card_1", "pr": 3 }),
            )),
            err(b::review::asked_in(
                &DEVPIT,
                &json!({ "card": "card_1", "bad": 3 }),
            )),
            err(b::review::asked_in(
                &DEVPIT,
                &json!({ "card": "card_1", "reports": [{}] }),
            )),
        ]
        .join("\n"),
    );
}

#[test]
fn a_whole_review_answers_records_and_comments_as_devpit_does() {
    pinned();
    let scratch = tempfile::tempdir().expect("scratch");
    let root = scratch.path().canonicalize().expect("root").join("review");
    std::fs::create_dir_all(&root).expect("root");
    let runs = b::runs::Runs {
        dialect: &DEVPIT,
        home: root.join("home"),
        checkout: root.clone(),
    };
    let config = b::config::parse(
        "version: 2\nstages:\n  - uses: builtin/review\nreview:\n  reviewers:\n    - { agent: claude, persona: devflow-security }\n  block_on: [critical, high]\n  consolidate: none\n",
    )
    .expect("review config");
    let answer = json!({
        "version": 1, "card": "card_1", "base": "b4se", "head": "he4d",
        "reviewers": [{ "agent": "claude", "persona": "devflow-security" }],
        "verdict": "approve",
        "findings": [],
        "done_well": ["kept it small"],
        "verification": { "tests": "ran them", "evidence": "green" },
    });
    let files = vec!["src/a.rs".to_owned()];
    let git = b::review::Git {
        base: "b4se",
        head: "he4d",
        files: &files,
        diff: DIFF,
    };
    let reach =
        |_agent: b::config::Agent| -> Result<String, String> { Err("not installed".to_owned()) };
    let asked = b::review::asked_in(&DEVPIT, &json!({ "card": "card_1" })).expect("asked");
    let lines = |_: &str, _: &str| -> Result<Option<usize>, String> { Ok(Some(10)) };
    let redact = |text: &str| text.to_owned();
    let given = b::review::Given {
        root: &root,
        runs: &runs,
        config: &config,
        asked: &asked,
        card: b::evidence::Card {
            id: "card_1",
            title: "Rename",
            body: "",
        },
        git: Some(git),
        brief: None,
        evidence: None,
        env: &[],
        at: at(0),
        budget: Duration::from_secs(600),
        reach: &reach,
        redact: &redact,
        jev: None,
        personas: personas(),
        previous: None,
        lines_at: &lines,
        retro: false,
    };
    let done = b::review::reviewed(&given).expect("reviewed");
    let masked = |text: &str| text.replace(&root.display().to_string(), "<ROOT>");
    same(
        "review-first-next",
        &masked(b::review::summary(&done)["next"].as_str().expect("next")),
    );
    same(
        "review-first-comment",
        &b::review::comment(&done, &[("p".into(), "x".into())]),
    );
    let mut handed = answer.clone();
    handed["reviewers"] = json!([{ "agent": "session", "persona": "devflow-spec" }]);
    let back = b::review::asked_in(
        &DEVPIT,
        &json!({ "card": "card_1", "run": done.stamp, "reports": [handed] }),
    )
    .expect("hand back");
    let again = b::review::reviewed(&b::review::Given {
        asked: &back,
        git: None,
        ..given
    })
    .expect("again");
    same(
        "review-again-summary",
        &masked(&pretty(&b::review::summary(&again))),
    );
    for file in ["findings.json", "review.json"] {
        let kept = std::fs::read_to_string(Path::new(&again.folder).join(file)).expect(file);
        same(
            &format!("review-run-{}", file.replace('.', "_")),
            &masked(&pretty_text(&kept)),
        );
    }
    for file in ["review-context.md", "devflow-findings.schema.json"] {
        let kept = std::fs::read_to_string(Path::new(&again.folder).join(file)).expect(file);
        same(
            &format!("review-run-{}", file.replace('.', "_")),
            &masked(&kept),
        );
    }
    same(
        "review-previous-error",
        &err(b::review::previous_of_in(
            &DEVPIT,
            &runs,
            "card_1",
            "20261011T000000Z",
        )),
    );
}

#[test]
fn a_review_without_a_card_says_what_is_next_in_devpits_words() {
    pinned();
    use b::adhoc::{next_in, standalone_in, Subject};
    let range = Subject::Range {
        base: "b".to_owned(),
        head: "h".to_owned(),
    };
    same(
        "adhoc-next",
        &[
            next_in(
                &DEVPIT,
                &Subject::Pr(7),
                "pr-7",
                "20261011T120000Z",
                &[],
                None,
                false,
            ),
            next_in(&DEVPIT, &range, "b-h", "20261011T120000Z", &[], None, true),
            next_in(
                &DEVPIT,
                &range,
                "b-h",
                "20261011T120000Z",
                &["devflow-spec".to_owned()],
                Some("he4d"),
                false,
            ),
        ]
        .join("\n"),
    );
    same(
        "adhoc-errors",
        &[
            err(standalone_in(&DEVPIT, &json!([]))),
            err(standalone_in(&DEVPIT, &json!({ "previous": "x" }))),
            err(standalone_in(&DEVPIT, &json!({ "criteria": ["a"] }))),
            err(standalone_in(
                &DEVPIT,
                &json!({ "pr": 3, "run": "20261011T120000Z" }),
            )),
        ]
        .join("\n"),
    );
}

#[test]
fn a_published_review_is_drafted_as_devpit_drafts_it() {
    pinned();
    use b::publish::{asked_in, draft, respond, template, Destination};
    let scratch = tempfile::tempdir().expect("scratch");
    let scratch = scratch.path();
    let kept = json!({
        "base": "b4se", "head": "he4d0123456789", "verdict": "request_changes",
        "findings": [
            { "file": "src/a.rs", "line": 2, "severity": "high", "axis": "security",
              "title": "Shell injection", "description": "why", "evidence": "the line",
              "poc": "curl", "agent": "claude", "persona": "devflow-security" },
            { "file": "src/b.rs", "line": 9, "severity": "low", "axis": "standards",
              "title": "A name", "description": "why", "evidence": "the line",
              "agent": "claude", "persona": "devflow-standards" },
        ],
        "done_well": ["kept it small"],
        "verification": { "tests": "ran them" },
        "pending": [],
    });
    let asked = asked_in(&DEVPIT, &json!({ "review": "pr-7/20261011T120000Z" })).expect("asked");
    let shipped = template(scratch, personas(), Destination::GitHub).expect("template");
    let drafted = draft(&kept, &asked, &shipped, b::config::Verify::Off);
    same("publish-draft", &pretty(&drafted));
    same(
        "publish-errors",
        &[
            err(asked_in(&DEVPIT, &json!({ "review": "nope" }))),
            err(respond(
                scratch,
                &asked,
                &shipped,
                b::config::Verify::Off,
                Err("no host"),
            )),
        ]
        .join("\n"),
    );
}

#[test]
fn runs_plans_and_configs_are_refused_in_devpits_words() {
    pinned();
    let scratch = tempfile::tempdir().expect("scratch");
    let runs = b::runs::Runs {
        dialect: &DEVPIT,
        home: scratch.path().join("h"),
        checkout: scratch.path().join("c"),
    };
    let plan = |cards: Value| err(b::plan::read_in(&DEVPIT, &cards));
    let slice = |key: &str, deps: Value| json!({ "key": key, "title": "T", "depends_on": deps });
    let jira = b::config::parse("version: 2\nstages:\n  - uses: builtin/plan\n    publish: jira\n")
        .expect("jira");
    same(
        "errors",
        &[
            err(runs.fresh("../x", at(0)).map(|_| ())),
            err(runs.file_in("card_1", Some("nope"), "f").map(|_| ())),
            plan(json!("x")),
            plan(json!([])),
            plan(json!([slice("a", json!(["zzz"]))])),
            plan(json!([slice("a", json!(["b"])), slice("b", json!(["a"]))])),
            err(b::plan::published_in(&DEVPIT, &jira)),
            b::config::parse_in(&DEVPIT, "version: 3\n")
                .expect_err("v3")
                .to_string(),
            b::preset::with_set_in(&DEVPIT, &b::Config::default(), "version", &json!(2))
                .expect_err("v")
                .to_string(),
        ]
        .join("\n"),
    );
}

#[test]
fn devflow_yaml_is_written_with_devpits_comments() {
    pinned();
    let v2 = b::config::parse(
        "version: 2\nenabled: true\nstages:\n  - uses: builtin/briefing\n  - uses: builtin/execution\n    checks:\n      - { name: unit, run: make test, report: junit }\n  - uses: builtin/review\n  - uses: project/pr\n    gate: { command: \"./pr.sh\" }\nreview:\n  reviewers:\n    - { agent: codex, persona: devflow-security }\ndecisions:\n  use: true\n  mode: shadow\n",
    )
    .expect("v2");
    same("yaml-v2", &b::render::render_in(&DEVPIT, &v2));
    let v1 = b::config::parse(
        "version: 1\nstages:\n  execution:\n    checks:\n      - { name: unit, run: make test, report: junit }\n",
    )
    .expect("v1");
    same("yaml-v1", &b::render::render_in(&DEVPIT, &v1));
}

#[test]
fn a_setup_detects_writes_and_recognises_devpits_scripts() {
    pinned();
    let scratch = tempfile::tempdir().expect("scratch");
    let project = scratch.path().join("node");
    std::fs::create_dir_all(&project).expect("project");
    for name in ["package.json", "playwright.config.ts", "pnpm-lock.yaml"] {
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/node")
                .join(name),
            project.join(name),
        )
        .expect("fixture");
    }
    let found = b::detect::detected_in(&DEVPIT, &project, Default::default());
    let commands: Vec<String> = found
        .test
        .iter()
        .chain(&found.e2e)
        .chain(&found.lint)
        .map(|one| one.command.clone())
        .collect();
    same("detect-commands", &commands.join("\n"));
    let layout = b::folder::Layout {
        dir: b::folder::LEGACY,
        file: b::locate::DEVPIT.to_owned(),
        dialect: &DEVPIT,
    };
    let made = b::proposal::setup_in(
        &layout,
        &b::State::Missing,
        b::preset::Preset::Recommended,
        &Default::default(),
        &found,
    )
    .expect("setup");
    same("setup-yaml", &made.yaml);
    let written = b::setup::write(&project, &made.files).expect("written");
    for file in &written {
        let text = std::fs::read_to_string(project.join(&file.path)).expect("read");
        let name = file.path.replace(['/', '.'], "_");
        same(&format!("setup-file{name}"), &text);
    }
    let mut config = made.config.clone();
    config
        .stages
        .execution
        .checks
        .retain(|check| check.name != "lint");
    let planned = b::setup::with_unused_in(&DEVPIT, &project, &config, Vec::new());
    let said: Vec<String> = b::setup::preview(&project, &planned)
        .iter()
        .map(|change| format!("{} {}", change.change, change.path))
        .collect();
    same("setup-unused", &said.join("\n"));
    same(
        "playwright-text",
        &b::playwright::text_of(
            &DEVPIT,
            b::folder::LEGACY,
            ".devpit/devflow/e2e",
            Some("playwright.config.ts"),
        ),
    );
}

#[test]
fn decisions_points_at_devpits_settings() {
    let state = |opted, key| {
        b::jev::decisions_state_in(&DEVPIT, true, opted, key, None)
            .reason
            .unwrap_or_default()
    };
    same(
        "jev-reasons",
        &[state(true, true), state(false, false)].join("\n"),
    );
}

fn sha(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

#[test]
fn the_skills_personas_rubrics_and_schema_served_are_devpits() {
    pinned();
    let empty = tempfile::tempdir().expect("empty");
    let empty = empty.path();
    let mut said = Vec::new();
    for name in b::skills::names() {
        let skill = b::skills::resolve_with_in(&DEVPIT, empty, empty, &[], name).expect("skill");
        said.push(pretty(&skill.to_json()));
    }
    for (name, stage, description) in b::skills::described_in(&DEVPIT) {
        said.push(format!("{name} {stage:?} {description}"));
    }
    same("assets-skills", &said.join("\n"));
    let mut said = Vec::new();
    for persona in [
        "devflow-spec",
        "devflow-standards",
        "devflow-security",
        "devflow-all",
    ] {
        let text = b::review::persona_text(empty, personas(), persona).expect("persona");
        said.push(format!("persona {persona} {}", sha(&text)));
    }
    for destination in b::publish::Destination::ALL {
        let text = b::publish::template(empty, personas(), destination).expect("template");
        said.push(format!("template {} {}", destination.word(), sha(&text)));
    }
    for name in [b::jev::FINDING, b::jev::BRIEF, b::jev::PLAN] {
        let text = DEVPIT.rubric(name).expect("rubric");
        said.push(format!("rubric {name} {}", sha(text)));
    }
    said.push(format!("schema {}", sha(DEVPIT.assets.schema)));
    same("assets-digests", &said.join("\n"));
}
