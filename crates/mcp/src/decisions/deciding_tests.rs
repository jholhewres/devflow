use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;

use serde_json::json;

use super::*;
use crate::decisions::rubric::Threshold;

fn decide_in(log: &Log, conf: &Conf, asking: &Asking<'_>, now: i64) -> Decided {
    decide_logged(log, conf, asking, now).0
}

fn log() -> (tempfile::TempDir, Log) {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = Log::at(&dir.path().join("decisions.jsonl"));
    (dir, log)
}

/// A provider on loopback answering one request with `status` and `reply`,
/// and handing back the request it read.
fn provider(status: &'static str, reply: &'static str) -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let base = format!(
        "http://127.0.0.1:{}/api/v1",
        listener.local_addr().expect("addr").port()
    );
    let (said, heard) = mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut request = String::new();
        let mut length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).expect("line");
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse().expect("length");
                }
            }
            request.push_str(&line);
            if line == "\r\n" {
                break;
            }
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).expect("body");
        request.push_str(&String::from_utf8_lossy(&body));
        let _ = said.send(request);
        let _ = write!(
            stream,
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
            reply.len()
        );
    });
    (base, heard)
}

fn conf(base: &str, key: Option<&str>) -> Conf {
    Conf {
        base: base.to_owned(),
        model: "typesafe/jev-1.13".to_owned(),
        cap_usd: 1.0,
        key: key.map(str::to_owned),
        secrets: vec!["supersecretvalue".to_owned()],
        ..Conf::default()
    }
}

fn asking<'a>(project_id: Option<&'a str>, state: &'a Value, questions: &'a Value) -> Asking<'a> {
    Asking {
        project_id,
        card_id: None,
        gate: "mcp.agent",
        mode: "shadow",
        rubric: None,
        state,
        questions,
    }
}

const ANSWERED: &str = r#"{"id":"gen-1","model":"typesafe/jev-1.13","answers":{"done":{"type":"noul","noul":0.91}},"usage":{"cost":0.0004}}"#;

#[test]
fn a_decision_asks_without_retention_and_reads_the_answers_and_cost() {
    let (_dir, log) = log();
    let (base, heard) = provider("200 OK", ANSWERED);
    let state = json!({ "diff": "token=supersecretvalue" });
    let questions = json!({ "done": { "type": "boolean", "instructions": "Is it done?" } });
    let decided = decide_in(
        &log,
        &conf(&base, Some("sk-or-test-key")),
        &asking(Some("/repo"), &state, &questions),
        1_000,
    );
    let Decided::Answered {
        answers, cost_usd, ..
    } = decided
    else {
        panic!("not answered: {decided:?}");
    };
    assert_eq!(answers["done"]["noul"], 0.91);
    assert!((cost_usd - 0.0004).abs() < 1e-12);
    let request = heard.recv().expect("a request");
    assert!(request.starts_with("POST /api/v1/systemone "), "{request}");
    assert!(request
        .to_lowercase()
        .contains("authorization: bearer sk-or-test-key"));
    let body: Value =
        serde_json::from_str(request.split("\r\n\r\n").nth(1).expect("body")).expect("json");
    assert_eq!(body["provider"]["zdr"], true);
    assert_eq!(body["provider"]["data_collection"], "deny");
    assert_eq!(body["questions"]["done"]["type"], "noul");
    let sent = body["state"].as_str().expect("the state, as text");
    assert!(!sent.contains("supersecretvalue") && sent.contains("[hidden by devflow]"));
    let logged = log.rows();
    assert_eq!(logged.len(), 1);
    assert_eq!(logged[0].outcome, "answered");
    assert_eq!(logged[0].mode, "shadow");
    assert!(!logged[0].state_digest.contains("token"));
}

#[test]
fn without_a_key_nothing_is_sent_and_nothing_logged() {
    let (_dir, log) = log();
    let state = json!("x");
    let questions = json!({ "done": { "type": "noul", "instructions": "?" } });
    let decided = decide_in(
        &log,
        &conf("http://127.0.0.1:9", None),
        &asking(None, &state, &questions),
        1_000,
    );
    assert_eq!(decided, Decided::Skipped(Skip::Off));
    assert!(log.rows().is_empty());
}

#[test]
fn a_spent_day_or_an_opted_out_project_skips_before_asking() {
    let (_dir, log) = log();
    log.write(Row {
        at: 1_000,
        gate: "g".to_owned(),
        mode: "shadow".to_owned(),
        questions: "{}".to_owned(),
        outcome: "pass".to_owned(),
        cost_usd: 1.5,
        state_digest: "x:1".to_owned(),
        ..Row::default()
    })
    .unwrap();
    let state = json!("x");
    let questions = json!({ "done": { "type": "noul", "instructions": "?" } });
    let spent = decide_in(
        &log,
        &conf("http://127.0.0.1:9", Some("k")),
        &asking(None, &state, &questions),
        1_000,
    );
    assert_eq!(spent, Decided::Skipped(Skip::Budget));
    let mut out = conf("http://127.0.0.1:9", Some("k"));
    out.opted_out = vec!["/repo".to_owned()];
    out.cap_usd = 100.0;
    assert_eq!(
        decide_in(
            &log,
            &out,
            &asking(Some("/repo"), &state, &questions),
            1_000
        ),
        Decided::Skipped(Skip::OptedOut)
    );
}

#[test]
fn a_refusal_is_a_skip_that_says_why_and_is_logged() {
    let (_dir, log) = log();
    let (base, _heard) = provider("401 Unauthorized", r#"{"error":{"message":"bad key"}}"#);
    let state = json!("x");
    let questions = json!({ "done": { "type": "noul", "instructions": "?" } });
    let decided = decide_in(
        &log,
        &conf(&base, Some("k")),
        &asking(Some("/repo"), &state, &questions),
        1_000,
    );
    let Decided::Skipped(Skip::Failed(why)) = decided else {
        panic!("not refused: {decided:?}");
    };
    assert!(why.contains("bad key"), "{why}");
    assert_eq!(log.failed_last("/repo").as_deref(), Some(why.as_str()));
}

#[test]
fn a_long_state_is_cut_after_its_secrets_are_taken_out() {
    let (short, cut) = prepared(&json!("a small state"), &[]);
    assert_eq!((short.as_str(), cut), ("a small state", false));

    // The secret straddles the cut: redacted first, no prefix of it survives.
    let long = format!("{}supersecretvalue", "a".repeat(MOST_STATE - 4));
    let (sent, cut) = prepared(&json!(long), &["supersecretvalue".to_owned()]);
    assert!(cut);
    assert_eq!(sent.chars().count(), MOST_STATE);
    assert!(!sent.contains("supe"));
}

#[test]
fn the_questions_go_out_as_the_wire_names_them() {
    let wire = wire_questions(&json!({ "a": { "type": "boolean" }, "b": {
        "type": "choice", "options": ["x", "y"], "criteria": { "x": "an x", "y": "a y" } } }))
    .expect("wire");
    assert_eq!(wire["a"]["type"], "noul");
    assert_eq!(wire["b"]["options"], json!(["x", "y"]));
    assert!(wire_questions(&json!({})).is_err());
    assert!(wire_questions(&json!({ "a": { "type": "essay" } })).is_err());
}

#[test]
fn a_choice_that_does_not_say_what_its_options_mean_is_refused_before_it_is_sent() {
    let unsaid =
        wire_questions(&json!({ "severity": { "type": "choice", "options": ["high", "low"] } }))
            .expect_err("no criteria");
    assert!(
        unsaid.contains("`severity`") && unsaid.contains("no criteria"),
        "{unsaid}"
    );
    let half = wire_questions(&json!({ "severity": { "type": "choice",
        "options": ["high", "low"], "criteria": { "high": "breaks a criterion", "low": " " } } }))
    .expect_err("one option unexplained");
    assert!(half.contains("`low` has none"), "{half}");
}

/// Every rubric devpit ships, as each is sent: one with a choice whose options
/// mean nothing to Decisions is refused on every call (devflow-finding was).
#[test]
fn every_rubric_devflow_ships_says_what_each_option_of_a_choice_means() {
    let shipped = devflow_engine::jev::BUILT_IN
        .iter()
        .chain(std::iter::once(&(
            devflow_engine::config::GATE,
            crate::flow::jev::DONE,
        )));
    for (name, text) in shipped {
        let rubric: Rubric = serde_json::from_str(text).expect(name);
        if let Err(why) = wire_questions(&rubric.questions) {
            panic!("the built-in rubric `{name}` would be refused: {why}");
        }
    }
    let per_criterion = crate::flow::jev::done_per_criterion(&["it works".to_owned()]);
    wire_questions(&per_criterion.questions).expect("devflow-done");
}

#[test]
fn a_gate_judges_the_answers_or_says_it_skipped() {
    let rubric = Rubric {
        name: "done".to_owned(),
        version: None,
        questions: json!({ "done": { "type": "noul" } }),
        thresholds: [(
            "done".to_owned(),
            Threshold {
                min: Some(0.8),
                grey: Some(0.5),
                ..Threshold::default()
            },
        )]
        .into(),
    };
    let answered = gated(
        Decided::Answered {
            answers: json!({ "done": { "type": "noul", "noul": 0.6 } }),
            cost_usd: 0.001,
            latency_ms: 10,
            truncated: false,
        },
        &rubric,
        "shadow".to_owned(),
    );
    assert_eq!(answered.outcome, "grey");
    assert_eq!(answered.answers["done"]["probability"], 0.6);
    let skipped = gated(Decided::Skipped(Skip::Off), &rubric, "shadow".to_owned());
    assert_eq!(skipped.outcome, "skipped");
    assert_eq!(skipped.skipped, Some(Skip::Off));
}
