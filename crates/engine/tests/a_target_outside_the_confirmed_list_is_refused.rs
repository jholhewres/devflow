//! A PoC is never run against a host the person did not confirm: a target
//! is in force only when devflow.yaml lists it and the person confirmed it,
//! and a PoC run said to have reached any other is refused, by the rule and
//! by the review that records it.

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use devflow_engine::{config, review, runs, security, Dialect};
use serde_json::{json, Value};

fn docker(hosts: &[(String, u16)]) -> Vec<Vec<IpAddr>> {
    hosts
        .iter()
        .map(|_| vec!["172.18.0.3".parse().expect("ip")])
        .collect()
}

fn ran(target: &str) -> Vec<Value> {
    vec![
        json!({ "finding": 0, "result": "confirmed", "evidence": "401 expected, got 200", "target": target }),
    ]
}

#[test]
fn a_target_outside_the_confirmed_list_is_refused() {
    let declared = vec![
        "http://localhost:8080".to_owned(),
        "http://api:8000".to_owned(),
    ];
    // The person confirmed only the first one on this machine.
    let confirmed = vec!["http://localhost:8080".to_owned()];
    let pins = security::Pins::from([(
        "http://localhost:8080".to_owned(),
        vec!["172.18.0.3".parse().expect("ip")],
    )]);
    let (in_force, left) = security::in_force(&declared, &confirmed, &pins, &docker);
    assert_eq!(in_force, ["http://localhost:8080"]);
    assert!(left[0].contains("not confirmed"), "{left:?}");

    assert!(security::refused(&ran("http://localhost:8080/login"), &in_force).is_ok());
    for outside in [
        "http://api:8000",
        "http://localhost:9090",
        "https://example.com",
        "http://localhost@example.com",
        "http://127.0.0.1.nip.io:8080",
    ] {
        let why = security::refused(&ran(outside), &in_force).expect_err(outside);
        assert!(why.contains("verified.0.target"), "{outside}: {why}");
    }
}

/// A review of `card_1` whose only reviewer is not installed, handed back by
/// the session with one high, so its run has a findings.json to verify.
fn reviewed_run(root: &std::path::Path, config: &config::Config) -> (runs::Runs, String) {
    let runs = runs::Runs {
        dialect: &Dialect::DEVFLOW,
        home: root.join("home"),
        checkout: root.to_path_buf(),
    };
    let files = vec!["src/auth/session.rs".to_owned()];
    let diff = "diff --git a/src/auth/session.rs b/src/auth/session.rs\n--- a/src/auth/session.rs\n+++ b/src/auth/session.rs\n@@ -1,1 +1,2 @@\n fn a() {}\n+fn b() {}\n";
    let reach = |_: config::Agent| -> Result<String, String> { Err("not installed".to_owned()) };
    let lines = |_: &str, _: &str| -> Result<Option<usize>, String> { Ok(Some(10)) };
    let redact = |text: &str| text.to_owned();
    let given =
        |asked: &review::Asked, git: Option<review::Git<'_>>| -> Result<review::Done, String> {
            review::reviewed(&review::Given {
                root,
                runs: &runs,
                config,
                asked,
                card: devflow_engine::evidence::Card {
                    id: "card_1",
                    title: "Sessions",
                    body: "",
                },
                git,
                brief: None,
                evidence: None,
                env: &[],
                at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_792_000_000),
                budget: Duration::from_secs(600),
                reach: &reach,
                redact: &redact,
                jev: None,
                personas: review::Personas::default(),
                previous: None,
                lines_at: &lines,
                retro: false,
            })
        };
    let first = review::asked(&json!({ "card": "card_1" })).expect("asked");
    let git = review::Git {
        base: "b4se",
        head: "he4d",
        files: &files,
        diff,
    };
    let done = given(&first, Some(git)).expect("first");
    let report = json!({
        "version": 1, "reviewers": [{ "agent": "session", "persona": "devflow-all" }],
        "verdict": "request_changes",
        "findings": [{
            "file": "src/auth/session.rs", "line": 2, "severity": "high", "axis": "security",
            "title": "a cookie signed with any key is accepted", "description": "spoofing",
            "evidence": "session.rs:2", "poc": "curl -b forged http://localhost:8080/me",
            "agent": "session", "persona": "devflow-all",
        }],
        "done_well": ["small"], "verification": { "tests": "read", "evidence": "none" },
    });
    let back = review::asked(&json!({ "card": "card_1", "run": done.stamp, "reports": [report] }))
        .expect("hand back");
    given(&back, None).expect("handed back");
    let stamp = done.stamp.clone();
    (runs, stamp)
}

fn verify(
    root: &std::path::Path,
    config: &config::Config,
    runs: &runs::Runs,
    stamp: &str,
    target: &str,
) -> Result<review::Done, String> {
    let reach = |_: config::Agent| -> Result<String, String> { Err("not installed".to_owned()) };
    let lines = |_: &str, _: &str| -> Result<Option<usize>, String> { Ok(Some(10)) };
    let redact = |text: &str| text.to_owned();
    let asked = review::asked(&json!({ "card": "card_1", "run": stamp, "verified": ran(target) }))
        .expect("verified");
    review::reviewed(&review::Given {
        root,
        runs,
        config,
        asked: &asked,
        card: devflow_engine::evidence::Card {
            id: "card_1",
            title: "Sessions",
            body: "",
        },
        git: None,
        brief: None,
        evidence: None,
        env: &[],
        at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_792_000_100),
        budget: Duration::from_secs(600),
        reach: &reach,
        redact: &redact,
        jev: None,
        personas: review::Personas::default(),
        previous: None,
        lines_at: &lines,
        retro: false,
    })
}

#[test]
fn a_review_records_no_poc_run_against_a_host_devflow_yaml_does_not_list() {
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().canonicalize().expect("root");
    let listed = config::parse(
        "version: 2\nreview:\n  reviewers:\n    - { agent: claude, persona: devflow-all }\nsecurity:\n  targets:\n    - http://localhost:8080\n",
    )
    .expect("listed");
    let (runs, stamp) = reviewed_run(&root, &listed);

    let why = verify(&root, &listed, &runs, &stamp, "http://localhost:9090").expect_err("outside");
    assert!(why.contains("not a target in force"), "{why}");
    let unlisted = config::parse("version: 2\n").expect("none listed");
    let why = verify(&root, &unlisted, &runs, &stamp, "http://localhost:8080").expect_err("none");
    assert!(why.contains("none is"), "{why}");

    let done = verify(&root, &listed, &runs, &stamp, "http://localhost:8080/me").expect("inside");
    let kept = &done.findings.expect("findings")["findings"][0]["verified"];
    assert_eq!(kept["target"], "http://localhost:8080/me");
}
