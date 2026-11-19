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
        .contains("cannot take this change in place"));
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

#[test]
fn a_project_on_devpits_folder_is_edited_in_place_too() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(".devpit/devflow/devflow.yaml");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    let text = "version: 1\nreview:\n  consolidate: jev # ours\n";
    std::fs::write(&file, text).unwrap();
    let mut session = started(dir.path(), false);
    let said = ask(
        &mut session,
        dir.path(),
        "config/write",
        json!({ "changes": [
            { "path": "review.consolidate", "value": "none" },
            { "path": "review.block_on", "value": ["critical"] },
        ] }),
    );
    assert_eq!(said["result"]["changed"], true, "{said}");
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "version: 1\nreview:\n  consolidate: none # ours\n  block_on:\n    - critical\n"
    );
}

#[test]
fn an_invalid_file_with_a_field_devflow_does_not_read_is_fixed_in_place() {
    let text = "version: 2\nenabled: maybe\nours:\n  kept: true\n";
    let dir = project(Some(text));
    let mut session = started(dir.path(), false);
    let said = ask(
        &mut session,
        dir.path(),
        "config/write",
        json!({ "changes": [{ "path": "enabled", "value": false }] }),
    );
    assert_eq!(said["result"]["changed"], true, "{said}");
    assert_eq!(on_file(dir.path()), text.replace("maybe", "false"));
    let typo = ask(
        &mut session,
        dir.path(),
        "config/write",
        json!({ "changes": [{ "path": "review.consolidat", "value": "none" }] }),
    );
    assert_eq!(typo["error"]["code"], FAILED, "{typo}");
}

#[test]
fn a_request_without_a_method_is_answered_with_its_id() {
    let dir = project(None);
    let said = answer(r#"{"jsonrpc":"2.0","id":9}"#, dir.path(), &mut None);
    let said: Value = serde_json::from_str(&said.reply.unwrap()).unwrap();
    assert_eq!(
        (said["id"].clone(), said["error"]["code"].clone()),
        (json!(9), json!(REQUEST))
    );
}

fn with_words(root: &Path, personal: &Path) -> Option<Session> {
    let mut session = None;
    ask(
        &mut session,
        root,
        "initialize",
        json!({
            "protocol": 1,
            "dialect": { "tools": {
                "evidence": "`devpit_devflow_evidence`",
                "item": "`devpit_card`",
            } },
            "personal": { "skills": personal },
        }),
    );
    session
}

#[test]
fn skills_are_listed_with_their_stage_and_where_they_come_from() {
    let dir = project(Some(FILE));
    let personal = tempfile::tempdir().unwrap();
    let mine = personal.path().join("devflow-plan/SKILL.md");
    std::fs::create_dir_all(mine.parent().unwrap()).unwrap();
    std::fs::write(
        &mine,
        "---\nname: devflow-plan\ndescription: My plan.\n---\n\nMine.\n",
    )
    .unwrap();
    let mut session = with_words(dir.path(), personal.path());
    let said = &ask(&mut session, dir.path(), "skills/list", json!({}))["result"]["skills"];
    let all = said.as_array().unwrap();
    assert_eq!(all.len(), 8, "{said}");
    let plan = all
        .iter()
        .find(|one| one["name"] == "devflow-plan")
        .unwrap();
    assert_eq!(plan["stage"], "plan");
    assert_eq!(plan["description"], "My plan.");
    assert_eq!(plan["source"]["layer"], "personal");
    let setup = all
        .iter()
        .find(|one| one["name"] == "devflow-setup")
        .unwrap();
    assert_eq!(
        (setup["stage"].clone(), setup["source"]["layer"].clone()),
        (Value::Null, json!("built-in"))
    );
}

#[test]
fn a_built_in_skill_is_got_in_the_hosts_words_with_its_digest() {
    use sha2::{Digest, Sha256};
    let dir = project(Some(FILE));
    let personal = tempfile::tempdir().unwrap();
    let mut session = with_words(dir.path(), personal.path());
    let said = &ask(
        &mut session,
        dir.path(),
        "skills/get",
        json!({ "name": "devflow-execution" }),
    )["result"];
    let text = said["text"].as_str().unwrap();
    assert!(text.contains("Read the item with `devpit_card`"), "{text}");
    assert!(text.contains("Call `devpit_devflow_evidence`"), "{text}");
    assert!(!text.contains("{{"));
    assert_eq!(
        said["sha256"],
        format!("{:x}", Sha256::digest(text.as_bytes()))
    );
    assert_eq!(said["source"]["layer"], "built-in");
    for (params, code) in [
        (
            json!({ "name": "devflow-execution", "part": "verify" }),
            PARAMS,
        ),
        (json!({ "name": "devflow-review", "part": "nope" }), PARAMS),
        (json!({ "name": "nope" }), PARAMS),
    ] {
        let refused = ask(&mut session, dir.path(), "skills/get", params);
        assert_eq!(refused["error"]["code"], code, "{refused}");
    }
}

#[test]
fn devpits_host_gets_devflows_skills_and_parts_in_devpits_words() {
    let dir = project(Some(FILE));
    let personal = tempfile::tempdir().unwrap();
    let mut session = None;
    ask(
        &mut session,
        dir.path(),
        "initialize",
        json!({ "protocol": 1, "dialect": { "host": "devpit" }, "personal": { "skills": personal.path() } }),
    );
    let listed = &ask(&mut session, dir.path(), "skills/list", json!({}))["result"]["skills"];
    let review = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|one| one["name"] == "devflow-review")
        .unwrap();
    assert_eq!(
        review["parts"],
        json!(["verify", "without-card", "retro", "publish", "by-hand"])
    );
    let brief = &ask(
        &mut session,
        dir.path(),
        "skills/get",
        json!({ "name": "devflow-briefing" }),
    )["result"];
    let text = brief["text"].as_str().unwrap();
    assert!(text.contains("an epic card on the board"), "{text}");
    assert!(!text.contains("[[") && !text.contains("{{"));
    let verify = &ask(
        &mut session,
        dir.path(),
        "skills/get",
        json!({ "name": "devflow-review", "part": "verify" }),
    )["result"];
    let text = verify["text"].as_str().unwrap();
    assert!(
        text.contains("for a card whose `devflow.yaml` sets"),
        "{text}"
    );
    assert_eq!(verify["source"]["layer"], "built-in");
}

#[test]
fn a_skill_comes_with_its_frontmatter_as_json() {
    let dir = project(Some(FILE));
    let personal = tempfile::tempdir().unwrap();
    let mut session = None;
    ask(
        &mut session,
        dir.path(),
        "initialize",
        json!({ "protocol": 1, "dialect": { "host": "devpit" }, "personal": { "skills": personal.path() } }),
    );
    let got = &ask(
        &mut session,
        dir.path(),
        "skills/get",
        json!({ "name": "devflow-plan" }),
    )["result"];
    assert_eq!(got["frontmatter"]["name"], "devflow-plan");
    assert!(
        got["frontmatter"]["description"]
            .as_str()
            .unwrap()
            .contains("cards"),
        "{got}"
    );
    let listed = &ask(&mut session, dir.path(), "skills/list", json!({}))["result"]["skills"];
    for entry in listed.as_array().unwrap() {
        assert_eq!(entry["frontmatter"]["name"], entry["name"], "{entry}");
    }
}

#[test]
fn a_folder_that_is_not_one_devflow_keeps_is_refused_before_anything_is_pinned() {
    let dir = project(None);
    let mut session = None;
    for folder in ["../elsewhere", ".devpit", "/tmp"] {
        let said = ask(
            &mut session,
            dir.path(),
            "initialize",
            json!({ "protocol": 1, "folder": folder }),
        );
        assert_eq!(said["error"]["code"], PARAMS, "{folder}: {said}");
    }
    assert!(devflow_engine::folder::pinned().is_none());
}
