use std::fs;

use super::*;

fn server(root: &Path) -> Server {
    Server {
        root: root.to_path_buf(),
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
    assert_eq!(said["result"]["structuredContent"]["state"], "found");
    assert_eq!(said["result"]["structuredContent"]["layout"], "root");
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
