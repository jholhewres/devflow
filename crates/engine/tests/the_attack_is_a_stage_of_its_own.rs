//! The attack is a stage after review: read as `stages.attack` in either
//! version, `review.attack` its older name, `sensitive` unless said. It keeps
//! a report of hypotheses with their exploits out of the checkout, and the
//! gate holds an item it is due on until it ran and what it confirmed is
//! shut.

use devflow_engine::config::{self, AttackRun, Config};
use devflow_engine::gate::{checked, Looked, Run};
use devflow_engine::{attack, models, Dialect};
use serde_json::{json, Value};

const SENSITIVE: &str = "src/auth/session.rs";
const DIFF: &str = "diff --git a/src/auth/session.rs b/src/auth/session.rs\n--- a/src/auth/session.rs\n+++ b/src/auth/session.rs\n@@ -1,1 +1,2 @@\n fn a() {}\n+let claims = decode_unverified(cookie);\n";

fn parsed(text: &str) -> Config {
    config::parse(text).expect(text)
}

#[test]
fn the_attack_stage_reads_in_either_version_with_review_attack_as_its_older_name() {
    for silent in [
        "version: 1\n",
        "version: 2\nstages:\n  - uses: builtin/review\n",
    ] {
        let config = parsed(silent);
        assert_eq!(config.stages.attack.run, AttackRun::Sensitive, "{silent}");
        assert!(config.stages_on().contains(&"attack"), "{silent}");
    }
    let v1 = parsed("version: 1\nstages:\n  attack: { run: per-item, model: large }\n");
    assert_eq!(v1.stages.attack.run, AttackRun::PerItem);
    assert_eq!(
        models::stage_model(&v1, models::ATTACK).as_deref(),
        Some("large")
    );
    let v2 = parsed(
        "version: 2\nstages:\n  - uses: builtin/review\n  - uses: builtin/attack\n    run: release\n  - uses: builtin/completion\n",
    );
    assert_eq!(v2.stages.attack.run, AttackRun::Release);
    let off = parsed("version: 2\nstages:\n  - uses: builtin/attack\n    enabled: false\n");
    assert!(!off.stages_on().contains(&"attack"));

    let older =
        parsed("version: 2\nreview:\n  attack: { run: per-item, model: claude-opus-5-5 }\n");
    assert_eq!(older.stages.attack.run, AttackRun::PerItem);
    assert_eq!(
        models::stage_model(&older, models::ATTACK).as_deref(),
        Some("claude-opus-5-5")
    );
    let written = devflow_engine::render::render(&older);
    assert!(written.contains("builtin/attack") && !written.contains("review:\n  attack"));
    assert_eq!(parsed(&written).stages, older.stages, "{written}");
    let twice = config::parse("version: 1\nstages:\n  attack: per-item\nreview:\n  attack: off\n")
        .expect_err("said twice, apart");
    assert_eq!(twice.field, "review.attack");

    let set = devflow_engine::preset::with_set(&older, "review.attack", &json!("off"))
        .expect("the older name is set where it is in force");
    assert_eq!(set.stages.attack.run, AttackRun::Off);
    let set = devflow_engine::preset::with_set(&v1, "stages.attack.run", &json!("release"))
        .expect("set by its name");
    assert_eq!(set.stages.attack.run, AttackRun::Release);
}

#[test]
fn the_attack_is_due_by_its_run_and_the_review_reads_no_attack() {
    let small = vec!["README.md".to_owned()];
    let readme = "diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-a\n+b\n";
    let sensitive = vec![SENSITIVE.to_owned()];
    let with = |run: &str| parsed(&format!("version: 2\nreview:\n  attack: {run}\n"));
    let due =
        |config: &Config, files: &[String], diff: &str| models::attack_on(config, files, diff);
    assert!(
        due(&Config::default(), &sensitive, DIFF),
        "sensitive unless said"
    );
    assert!(!due(&Config::default(), &small, readme));
    assert!(due(&with("per-item"), &small, readme));
    assert!(
        !due(&with("release"), &sensitive, DIFF),
        "a release's is asked by name"
    );
    assert!(!due(&with("off"), &sensitive, DIFF));
    let asked = models::attack_asked(&with("release")).expect("asked by name");
    assert!(due(&asked, &small, readme));
    assert!(models::attack_asked(&with("off")).is_err());
    for config in [with("per-item"), Config::default()] {
        assert!(
            models::readers(&config, false, &sensitive, DIFF)
                .iter()
                .all(|reader| reader.stage != models::ATTACK),
            "the review reads; the attack is its own stage"
        );
    }
    assert_eq!(
        models::stage_model(&Config::default(), models::ATTACK).as_deref(),
        Some("large")
    );
}

/// A Claude Code that answers with `answer`, in its envelope.
#[cfg(unix)]
fn fake_claude(dir: &std::path::Path, answer: &Value) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let envelope =
        json!({ "type": "result", "result": answer.to_string(), "total_cost_usd": 0.42 });
    std::fs::write(dir.join("answer.json"), envelope.to_string()).expect("answer");
    let script = dir.join("claude");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\ncat > /dev/null\ncat '{}/answer.json'\n",
            dir.display()
        ),
    )
    .expect("script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("mode");
    script
}

#[cfg(unix)]
#[test]
fn the_attack_keeps_each_hypothesis_and_its_exploits_out_of_the_checkout() {
    use std::time::{Duration, SystemTime};
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().canonicalize().expect("root");
    let checkout = root.join("checkout");
    std::fs::create_dir_all(&checkout).expect("checkout");
    let code = "test('a cookie signed with another key is refused', () => {})";
    let claude = fake_claude(
        &root,
        &json!({ "version": 1, "hypotheses": [
            { "id": "h1", "title": "a cookie signed with any key is accepted", "class": "authn",
              "file": SENSITIVE, "line": 2, "severity": "high", "status": "confirmed",
              "reason": "the signature is never checked", "from": "r0",
              "exploit": { "path": "tests/session.exploit.test.ts", "test": "a cookie signed with another key is refused", "code": code } },
            { "id": "h2", "title": "the cookie is read over plain http", "file": SENSITIVE, "line": 1,
              "severity": "medium", "status": "refuted", "reason": "the server only listens on TLS" },
            { "id": "h3", "title": "a replayed cookie after logout", "file": SENSITIVE, "line": 2,
              "severity": "medium", "status": "not_run", "reason": "needs the running app and no target is in force" },
        ] }),
    );
    let reach =
        move |_: config::Agent| -> Result<String, String> { Ok(claude.display().to_string()) };
    let redact = |text: &str| text.to_owned();
    let runs = devflow_engine::runs::Runs {
        dialect: &Dialect::DEVFLOW,
        home: root.join("home"),
        checkout: checkout.clone(),
    };
    let config = Config::default();
    let files = vec![SENSITIVE.to_owned()];
    let review = json!({ "findings": [
        { "axis": "security", "title": "unsigned cookie", "file": SENSITIVE, "line": 2, "severity": "high", "description": "d", "poc": "p" },
        { "axis": "spec", "title": "not security", "file": "a.rs", "line": 1, "severity": "high" },
    ] });
    assert_eq!(attack::from_review(Some(&review)).len(), 1);
    let done = attack::attacked(&attack::Given {
        root: &checkout,
        runs: &runs,
        config: &config,
        card: devflow_engine::evidence::Card {
            id: "card_1",
            title: "Sessions",
            body: "",
        },
        git: devflow_engine::review::Git {
            base: "b4se",
            head: "he4d",
            files: &files,
            diff: DIFF,
        },
        brief: None,
        evidence: None,
        review: Some(&review),
        env: &[],
        at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_792_000_000),
        budget: Duration::from_secs(60),
        reach: &reach,
        redact: &redact,
        personas: devflow_engine::review::Personas::default(),
        retro: false,
    })
    .expect("attacked");
    let report = &done.report;
    let statuses: Vec<&str> = report["hypotheses"]
        .as_array()
        .expect("hypotheses")
        .iter()
        .filter_map(|one| one["status"].as_str())
        .collect();
    assert_eq!(
        statuses,
        ["tried", "refuted", "not_run"],
        "only a run confirms"
    );
    assert!(report["hypotheses"][0]["reason"]
        .as_str()
        .expect("reason")
        .starts_with("only a run"));
    assert_eq!(report["hypotheses"][0]["from"], "r0");
    assert_eq!(report["verdict"], "approve");
    assert_eq!(report["attackers"][0]["cost_usd"], 0.42);
    let saved = report["hypotheses"][0]["exploit"]["saved"]
        .as_str()
        .expect("saved");
    let folder = std::path::Path::new(&done.folder);
    assert_eq!(
        std::fs::read_to_string(folder.join(saved)).expect("kept"),
        code
    );
    assert!(
        !report.to_string().contains(code),
        "the report names the file, not the code"
    );
    assert!(folder.join(attack::REPORT).is_file());
    let written: Vec<_> = std::fs::read_dir(&checkout)
        .expect("checkout")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .collect();
    assert!(written.is_empty(), "nothing in the checkout: {written:?}");

    let refused = attack::verified(
        folder,
        &config,
        &[
            json!({ "hypothesis": "h1", "result": "confirmed", "evidence": "red" , "target": "http://example.com" }),
        ],
    );
    assert!(
        refused.is_err(),
        "a run against a host not in force is refused"
    );
    let report = attack::verified(
        folder,
        &config,
        &[json!({ "hypothesis": "h1", "result": "confirmed", "evidence": "red in run r2" })],
    )
    .expect("confirmed");
    assert_eq!(report["verdict"], "request_changes");
    assert_eq!(report["counts"]["confirmed"], 1);
    assert_eq!(
        attack::exploits(&report)[0]["test"],
        "a cookie signed with another key is refused"
    );
}

#[test]
fn an_attackers_answer_is_held_to_its_shape() {
    let refused = |answer: Value| attack::read_answer(&answer.to_string()).expect_err("refused");
    assert!(refused(json!({ "nothing": [] })).contains("hypotheses"));
    assert!(refused(json!({ "hypotheses": [{ "title": "t", "severity": "high", "status": "tried", "reason": "r" }] }))
        .contains("exploit"));
    assert!(refused(
        json!({ "hypotheses": [{ "title": "t", "severity": "high", "status": "tried", "reason": "r",
        "exploit": { "path": "../outside.test.ts", "test": "t", "code": "c" } }] })
    )
    .contains("no `..`"));
    assert!(refused(json!({ "hypotheses": [{ "title": "t", "severity": "grave", "status": "refuted", "reason": "r" }] }))
        .contains("severity"));
}

fn looked_with<'a>(
    config: &'a Config,
    evidence: &'a Value,
    stages: &'a [(String, Option<(String, Value)>)],
    changed: Option<&'a str>,
) -> Looked<'a> {
    Looked {
        dialect: &Dialect::DEVFLOW,
        config,
        card: "card_1",
        criteria: &[],
        run: Some(Run {
            name: "20261119T120000Z",
            evidence,
        }),
        review: None,
        changed,
        stages,
        unreviewed: None,
        no_code: true,
    }
}

#[test]
fn the_gate_holds_an_item_the_attack_is_due_on_until_it_ran_and_its_holes_are_shut() {
    let config = parsed("version: 2\nstages:\n  - uses: builtin/execution\n    checks:\n      - { name: unit, run: make test, report: junit }\n");
    let evidence = |green: bool| {
        json!({ "checks": [{ "name": "unit", "result": "passed" }], "red": if green {
            json!([{ "test": "exploit", "now": "passed" }])
        } else { json!([]) } })
    };
    let missing =
        |stages: &[(String, Option<(String, Value)>)], green: bool, changed: Option<&str>| {
            let evidence = evidence(green);
            checked(&looked_with(&config, &evidence, stages, changed)).missing
        };
    let attack = |stages: &str| stages.contains("attack stage");
    let due_not_run = vec![(config::ATTACK.to_owned(), None)];
    assert!(missing(&due_not_run, true, None)
        .iter()
        .any(|said| attack(said)));
    assert!(
        !missing(&[], true, None).iter().any(|said| attack(said)),
        "not due, not held"
    );

    let report = json!({ "hypotheses": [{ "id": "h1", "status": "confirmed", "severity": "high",
        "file": SENSITIVE, "line": 2, "title": "unsigned cookie", "exploit": { "test": "exploit" } }] });
    let ran = vec![(
        config::ATTACK.to_owned(),
        Some(("20261119T110000Z".to_owned(), report)),
    )];
    let red = missing(&ran, false, None);
    assert!(
        red.iter()
            .any(|said| said.contains("the exploit test `exploit`")),
        "{red:?}"
    );
    let green = missing(&ran, true, Some("20261119T115959Z"));
    assert!(
        green
            .iter()
            .all(|said| !said.contains("exploit") && !attack(said)),
        "{green:?}"
    );

    let per_item = parsed("version: 1\nstages:\n  attack: per-item\n");
    let evidence = evidence(true);
    let older = checked(&looked_with(
        &per_item,
        &evidence,
        &ran,
        Some("20261119T115959Z"),
    ))
    .missing;
    assert!(
        older
            .iter()
            .any(|said| said.contains("older than the last change")),
        "{older:?}"
    );
}
