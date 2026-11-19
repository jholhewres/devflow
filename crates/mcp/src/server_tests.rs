use std::fs;

use super::*;

fn server(root: &Path) -> Server {
    Server {
        cwd: root.to_path_buf(),
        consent: Consent::at(&root.join(".consent")),
        preview: Mutex::new(None),
    }
}

fn answer(line: &str, root: &Path) -> Value {
    serde_json::from_str(&handle(line, &server(root)).unwrap()).unwrap()
}

#[test]
fn the_handshake_speaks_the_clients_revision_when_it_knows_it() {
    assert_eq!(protocol(Some("2025-03-26")), "2025-03-26");
    assert_eq!(protocol(Some("1999-01-01")), PROTOCOLS[0]);
    assert_eq!(protocol(None), PROTOCOLS[0]);

    let dir = tempfile::tempdir().unwrap();
    let said = answer(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
        dir.path(),
    );
    assert_eq!(said["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(said["result"]["serverInfo"]["name"], "devflow");
}

#[test]
fn a_notification_gets_no_answer() {
    let dir = tempfile::tempdir().unwrap();
    let line = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    assert_eq!(handle(line, &server(dir.path())), None);
}

#[test]
fn what_is_not_json_is_a_parse_error() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(answer("{not json", dir.path())["error"]["code"], -32700);
}

#[test]
fn an_unknown_method_is_refused_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let said = answer(
        r#"{"jsonrpc":"2.0","id":2,"method":"sampling/createMessage"}"#,
        dir.path(),
    );
    assert_eq!(said["error"]["code"], -32601);
}

#[test]
fn every_listed_tool_has_a_schema() {
    let dir = tempfile::tempdir().unwrap();
    let said = answer(
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#,
        dir.path(),
    );
    let listed = said["result"]["tools"].as_array().unwrap();
    assert!(!listed.is_empty());
    assert!(listed
        .iter()
        .all(|tool| tool["inputSchema"]["type"] == "object"));
}

#[test]
fn status_names_the_projects_configuration() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("devflow.yaml"), "version: 2\n").unwrap();
    let said = answer(
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"status"}}"#,
        dir.path(),
    );
    assert_eq!(said["result"]["isError"], false);
    assert_eq!(said["result"]["structuredContent"]["state"], "disabled");
    assert_eq!(said["result"]["structuredContent"]["file"], "devflow.yaml");
    let models = &said["result"]["structuredContent"]["models"];
    assert_eq!(models["preset"], "economy");
    assert_eq!(models["session"], "sonnet");
    assert_eq!(models["analysis"], false);
}

#[test]
fn a_tools_answer_is_compact_json_that_reads_as_its_structured_content() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("devflow.yaml"), "version: 2\n").unwrap();
    let said = answer(
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"status"}}"#,
        dir.path(),
    );
    let text = said["result"]["content"][0]["text"].as_str().unwrap();
    assert!(!text.contains('\n'));
    let read: Value = serde_json::from_str(text).unwrap();
    assert_eq!(read, said["result"]["structuredContent"]);
}

#[test]
fn an_unknown_tool_is_the_tools_error_not_the_protocols() {
    let dir = tempfile::tempdir().unwrap();
    let said = answer(
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nope"}}"#,
        dir.path(),
    );
    assert_eq!(said["result"]["isError"], true);
}

#[test]
fn the_skills_are_prompts_and_resources_too() {
    let dir = tempfile::tempdir().unwrap();
    let prompts = answer(
        r#"{"jsonrpc":"2.0","id":6,"method":"prompts/list"}"#,
        dir.path(),
    );
    let listed = prompts["result"]["prompts"].as_array().unwrap();
    assert!(listed.iter().any(|one| one["name"] == "devflow-plan"));
    let read = answer(
        r#"{"jsonrpc":"2.0","id":7,"method":"resources/read","params":{"uri":"skill://devflow/devflow-plan/SKILL.md"}}"#,
        dir.path(),
    );
    assert!(read["result"]["contents"][0]["text"]
        .as_str()
        .unwrap()
        .contains("name: devflow-plan"));
    let missing = answer(
        r#"{"jsonrpc":"2.0","id":8,"method":"prompts/get","params":{"name":"nope"}}"#,
        dir.path(),
    );
    assert_eq!(missing["error"]["code"], -32602);
}

#[test]
fn a_skills_part_is_served_by_the_tool_and_as_a_resource() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path());
    let listed = handle(
        r#"{"jsonrpc":"2.0","id":1,"method":"resources/list"}"#,
        &server,
    )
    .unwrap();
    assert!(
        listed.contains("skill://devflow/devflow-review/verify.md"),
        "{listed}"
    );
    let read = handle(
        r#"{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"skill://devflow/devflow-review/retro.md"}}"#,
        &server,
    )
    .unwrap();
    assert!(read.contains("retro, code already in production"), "{read}");
    let said = crate::flow::skill::skill(
        &server,
        serde_json::json!({ "name": "devflow-review", "part": "by-hand" }),
    )
    .unwrap();
    assert!(said["text"]
        .as_str()
        .unwrap()
        .contains("When `review` is not listed"));
}

#[test]
fn a_part_is_asked_with_or_without_its_extension_and_an_unknown_one_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path());
    let ask = |params: serde_json::Value| crate::flow::skill::skill(&server, params);
    let with = ask(serde_json::json!({ "name": "devflow-review", "part": "verify.md" })).unwrap();
    let without = ask(serde_json::json!({ "name": "devflow-review", "part": "verify" })).unwrap();
    assert_eq!(with["text"], without["text"]);
    let main = ask(serde_json::json!({ "name": "devflow-review", "part": "SKILL.md" })).unwrap();
    assert_eq!(main["name"], "devflow-review");
    let why =
        ask(serde_json::json!({ "uri": "skill://devflow/devflow-review/nope.md" })).unwrap_err();
    assert!(why.contains("has no part `nope`"), "{why}");
}

#[test]
fn the_evidence_tool_says_release_checks_run_only_when_named() {
    let config = devflow_engine::config::parse(
        "version: 2\nstages:\n  - uses: builtin/execution\n    checks:\n      - { name: unit, run: make test, report: junit }\n    release:\n      - { name: e2e, run: make e2e, report: junit }\n",
    )
    .expect("a config");
    let names = |named: Option<&[String]>| -> Vec<String> {
        let runnable = config.stages.execution.runnable(named);
        runnable.into_iter().map(|check| check.name).collect()
    };
    assert_eq!(names(None), ["unit"]);
    assert_eq!(names(Some(&["e2e".to_owned()])), ["unit", "e2e"]);

    let dir = tempfile::tempdir().unwrap();
    let said = answer(
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#,
        dir.path(),
    );
    let evidence = said["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "evidence")
        .unwrap();
    let checks = evidence["inputSchema"]["properties"]["checks"]["description"]
        .as_str()
        .unwrap();
    for text in [evidence["description"].as_str().unwrap(), checks] {
        assert!(text.contains("release"), "{text}");
        assert!(!text.contains("to run all"), "{text}");
    }
}
