use super::*;

const FILE: &str = "\
# Ours: ask before changing the gate.
version: 2
enabled: false   # the app flips it
ours:
  kept: true     # devflow does not read this
review:
  consolidate: none
";

fn project(text: Option<&str>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    if let Some(text) = text {
        std::fs::create_dir_all(dir.path().join(".devflow")).unwrap();
        std::fs::write(dir.path().join(".devflow/devflow.yaml"), text).unwrap();
    }
    dir
}

fn on_file(dir: &Path) -> String {
    std::fs::read_to_string(dir.join(".devflow/devflow.yaml")).unwrap()
}

/// The reply to one request, as JSON.
fn ask(session: &mut Option<Session>, root: &Path, method: &str, params: Value) -> Value {
    let line = json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": params });
    let answer = answer(&line.to_string(), root, session);
    serde_json::from_str(&answer.reply.expect("a request is answered")).unwrap()
}

fn started(root: &Path, enabled: bool) -> Option<Session> {
    let mut session = None;
    let said = ask(
        &mut session,
        root,
        "initialize",
        json!({
            "protocol": 1,
            "host": { "name": "devpit", "version": "1.0.0" },
            "root": root,
            "consent": { "enabled": enabled, "enforce": false },
        }),
    );
    assert_eq!(said["result"]["protocol"], 1, "{said}");
    session
}

#[test]
fn initialize_says_the_version_methods_and_tools() {
    let dir = project(None);
    let mut session = None;
    let said = ask(
        &mut session,
        dir.path(),
        "initialize",
        json!({ "protocol": 1 }),
    );
    assert_eq!(said["id"], 7);
    assert_eq!(said["result"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(said["result"]["methods"], json!(METHODS));
    assert_eq!(said["result"]["tools"], json!(["status"]));
    assert!(session.is_some());
}

#[test]
fn a_protocol_this_devflow_does_not_speak_is_refused() {
    let dir = project(None);
    let mut session = None;
    let said = ask(
        &mut session,
        dir.path(),
        "initialize",
        json!({ "protocol": 2 }),
    );
    assert_eq!(said["error"]["code"], PARAMS);
    assert!(said["error"]["message"]
        .as_str()
        .unwrap()
        .contains("speaks protocols [1]"));
    assert!(session.is_none());
}

#[test]
fn a_method_before_initialize_and_one_not_served_are_told_apart() {
    let dir = project(None);
    let mut session = None;
    let said = ask(&mut session, dir.path(), "config/read", json!({}));
    assert_eq!(said["error"]["code"], NOT_STARTED);
    let mut session = started(dir.path(), false);
    let said = ask(&mut session, dir.path(), "plan/validate", json!({}));
    assert_eq!(said["error"]["code"], NO_METHOD);
    let said = ask(&mut session, dir.path(), "tool", json!({ "name": "gate" }));
    assert_eq!(said["error"]["code"], NO_METHOD);
    let said = ask(&mut session, dir.path(), "tool", json!({ "name": "nope" }));
    assert_eq!(said["error"]["code"], PARAMS);
}

#[test]
fn a_notification_is_not_answered_and_shutdown_ends_the_call() {
    let dir = project(None);
    let mut session = started(dir.path(), false);
    let quiet = answer(
        r#"{"jsonrpc":"2.0","method":"note"}"#,
        dir.path(),
        &mut session,
    );
    assert!(quiet.reply.is_none() && !quiet.last);
    let line = r#"{"jsonrpc":"2.0","id":1,"method":"shutdown"}"#;
    assert!(answer(line, dir.path(), &mut session).last);
    let bad = answer("not json", dir.path(), &mut session);
    assert!(bad.reply.unwrap().contains(&PARSE.to_string()));
}

#[test]
fn config_read_says_the_file_its_state_and_what_this_devflow_does_not_read() {
    let missing = project(None);
    let mut session = started(missing.path(), false);
    let said = ask(&mut session, missing.path(), "config/read", json!({}));
    assert_eq!(said["result"]["state"], "missing");

    let dir = project(Some(FILE));
    let mut session = started(dir.path(), false);
    let said = &ask(&mut session, dir.path(), "config/read", json!({}))["result"];
    assert_eq!(said["state"], "valid", "{said}");
    assert_eq!(said["file"], ".devflow/devflow.yaml");
    assert_eq!(said["config"]["review"]["consolidate"], "none");
    assert_eq!(said["unread"][0]["field"], "ours", "{said}");

    let broken = project(Some("version: 2\nenabled: maybe\n"));
    let mut session = started(broken.path(), false);
    let said = &ask(&mut session, broken.path(), "config/read", json!({}))["result"];
    assert_eq!(said["state"], "invalid");
    assert_eq!(said["invalid"]["line"], 2);
    assert_eq!(said["config"]["enabled"], "maybe");
}

#[test]
fn config_write_keeps_the_comments_and_the_fields_devflow_does_not_read() {
    let dir = project(Some(FILE));
    let mut session = started(dir.path(), false);
    let said = &ask(
        &mut session,
        dir.path(),
        "config/write",
        json!({ "changes": [
            { "path": "review.consolidate", "value": "agent" },
            { "path": "review.block_on", "value": ["critical"] },
        ] }),
    )["result"];
    assert_eq!(said["changed"], true, "{said}");
    assert_eq!(said["laid_out"], false);
    assert_eq!(said["before"]["review"]["consolidate"], "none");
    assert_eq!(said["after"]["review"]["block_on"], json!(["critical"]));
    assert_eq!(
        on_file(dir.path()),
        FILE.replace(
            "  consolidate: none\n",
            "  consolidate: agent\n  block_on:\n    - critical\n"
        )
    );
}

#[test]
fn only_the_persons_click_switches_devflow_on() {
    let dir = project(Some(FILE));
    let mut session = started(dir.path(), false);
    let change = json!({ "changes": [{ "path": "enabled", "value": true }] });
    let said = &ask(&mut session, dir.path(), "config/write", change.clone())["result"];
    assert_eq!(said["asks"], json!(["enable"]));
    assert_eq!(said["changed"], false);
    assert_eq!(on_file(dir.path()), FILE);

    let mut clicked = change;
    clicked["by"] = json!("person");
    let said = &ask(&mut session, dir.path(), "config/write", clicked)["result"];
    assert_eq!(said["changed"], true, "{said}");
    assert_eq!(
        on_file(dir.path()),
        FILE.replace("enabled: false   #", "enabled: true   #")
    );
}

#[test]
fn what_an_attack_may_reach_is_never_written_by_a_host() {
    let dir = project(Some(FILE));
    let mut session = started(dir.path(), false);
    let said = ask(
        &mut session,
        dir.path(),
        "config/write",
        json!({ "by": "person", "changes": [
            { "path": "security.targets", "value": ["http://localhost:8080"] },
        ] }),
    );
    assert_eq!(said["error"]["code"], PARAMS);
    assert_eq!(on_file(dir.path()), FILE);
}

#[test]
fn a_change_that_cannot_be_made_in_place_is_refused_and_writes_nothing() {
    let text = "version: 2\nenabled: false\nreview: { consolidate: none }\n";
    let dir = project(Some(text));
    let mut session = started(dir.path(), false);
    let said = ask(
        &mut session,
        dir.path(),
        "config/write",
        json!({ "changes": [{ "path": "review.block_on", "value": ["critical"] }] }),
    );
    assert_eq!(said["error"]["code"], FAILED, "{said}");
    assert!(said["error"]["message"]
        .as_str()
        .unwrap()
        .contains("cannot be edited in place"));
    assert_eq!(on_file(dir.path()), text);
}

#[test]
fn status_reads_the_hosts_switch_not_the_consent_file() {
    let dir = project(Some(&FILE.replace("enabled: false", "enabled: true ")));
    let mut off = started(dir.path(), false);
    let mut on = started(dir.path(), true);
    let status = json!({ "name": "status" });
    let said_off = &ask(&mut off, dir.path(), "tool", status.clone())["result"];
    let said_on = &ask(&mut on, dir.path(), "tool", status)["result"];
    for key in [
        "state", "file", "folder", "next", "note", "unread", "models",
    ] {
        assert!(said_on.get(key).is_some(), "{key}: {said_on}");
    }
    assert_ne!(said_off["state"], said_on["state"], "{said_off} {said_on}");
}
