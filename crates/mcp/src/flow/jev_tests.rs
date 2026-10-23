use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;

use super::*;

/// A provider on loopback answering every request with `reply`.
fn provider(reply: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let base = format!(
        "http://127.0.0.1:{}/api/v1",
        listener.local_addr().unwrap().port()
    );
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut length = 0;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        length = value.trim().parse().unwrap_or(0);
                    }
                }
                if line == "\r\n" {
                    break;
                }
            }
            let mut body = vec![0; length];
            let _ = reader.read_exact(&mut body);
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                reply.len()
            );
        }
    });
    base
}

fn project() -> (tempfile::TempDir, Project) {
    let dir = tempfile::tempdir().unwrap();
    let project = Project {
        root: dir.path().canonicalize().unwrap(),
    };
    (dir, project)
}

fn jev(project: &Project, log: Log, base: &str, key: Option<&str>, mode: Mode) -> Jev {
    let conf = Conf {
        base: base.to_owned(),
        model: "typesafe/jev-1.13".to_owned(),
        cap_usd: 1.0,
        key: key.map(str::to_owned),
        ..Conf::default()
    };
    Jev::with(
        log,
        conf,
        project,
        Some("3"),
        mode,
        &["it renames".to_owned()],
    )
}

const DONE_ANSWERS: &str = r#"{"answers":{"criterion1":{"type":"noul","noul":0.95},"verified":{"type":"noul","noul":0.9},"inScope":{"type":"noul","noul":0.92}},"usage":{"cost":0.001}}"#;

#[test]
fn the_done_rubric_asks_each_criterion_and_is_logged_under_its_mode() {
    let (dir, project) = project();
    let log = Log::at(&dir.path().join("log.jsonl"));
    let base = provider(DONE_ANSWERS);
    let jev = jev(&project, log.clone(), &base, Some("sk-or-k"), Mode::Shadow);
    assert!(jev.answers());
    let said = jev.judge(GATE, &json!({ "criteria": ["it renames"] }));
    assert_eq!(said.outcome, "pass", "{said:?}");
    assert_eq!(said.mode, Mode::Shadow);
    assert!(said.decision.is_some());
    let rows = log.rows();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].questions.contains("criterion1"));
    assert_eq!(jev.state().state, devflow_engine::jev::DecisionsState::On);
    finished_label(&project, &log, &rows[0].id);
}

fn finished_label(project: &Project, log: &Log, id: &str) {
    let _ = project;
    log.label(id, true, "finished").unwrap();
    assert_eq!(log.rows()[0].person_verdict.as_deref(), Some("pass"));
}

#[test]
fn without_a_key_each_answer_says_it_skipped() {
    let (dir, project) = project();
    let jev = jev(
        &project,
        Log::at(&dir.path().join("log.jsonl")),
        "http://127.0.0.1:9",
        None,
        Mode::Shadow,
    );
    assert!(!jev.answers());
    let said = jev.judge(GATE, &json!({}));
    assert_eq!(said.outcome, "skipped");
    assert!(said.skipped.unwrap().contains("devflow jev setup"));
    assert_eq!(
        jev.state().state,
        devflow_engine::jev::DecisionsState::NoKey
    );
}

#[test]
fn the_finding_rubric_stays_in_shadow_until_the_persons_labels_say_otherwise() {
    let (dir, project) = project();
    let jev = jev(
        &project,
        Log::at(&dir.path().join("log.jsonl")),
        "http://127.0.0.1:9",
        Some("k"),
        Mode::Enforce,
    );
    let finding = rubric(&project.root, rules::FINDING, &[]).unwrap();
    assert_eq!(jev.mode_for(rules::FINDING, &finding), Mode::Shadow);
    let done = rubric(&project.root, GATE, &[]).unwrap();
    assert_eq!(jev.mode_for(GATE, &done), Mode::Enforce);
}

#[test]
fn a_projects_own_rubric_replaces_devflows() {
    let (_dir, project) = project();
    let folder = project.root.join(".devflow/rubrics");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(
        folder.join("devflow-plan.json"),
        r#"{ "questions": { "ours": { "type": "noul", "instructions": "Ours?" } } }"#,
    )
    .unwrap();
    let ours = rubric(&project.root, rules::PLAN, &[]).unwrap();
    assert!(ours.questions.get("ours").is_some());
    assert!(rubric(&project.root, "../x", &[]).is_err());
    let per = done_per_criterion(&["a".to_owned(), "b".to_owned()]);
    assert!(per.questions.get("criterion2").is_some());
    assert!(per.questions.get("criteriaMet").is_none());
}
