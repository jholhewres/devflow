use std::fs;

use super::*;

fn machine(home: &Path, said: Option<&'static str>) -> Machine {
    Machine {
        home: home.to_path_buf(),
        config: home.join(".config"),
        mac: false,
        has: Box::new(|_| true),
        ask: Box::new(move |_| said.map(str::to_owned)),
    }
}

#[test]
fn an_entry_is_added_beside_the_persons_own_in_their_order() {
    let text = r#"{ "zeta": 1, "mcpServers": { "other": { "command": "x" } }, "alpha": 2 }"#;
    let value = json!({ "command": "/bin/devflow", "args": ["mcp"] });
    let new = put(Some(text), "mcpServers", &value).unwrap().unwrap();
    let doc: Value = serde_json::from_str(&new).unwrap();

    assert_eq!(doc["mcpServers"]["other"]["command"], "x");
    assert_eq!(doc["mcpServers"]["devflow"], value);
    assert!(new.find("zeta").unwrap() < new.find("alpha").unwrap());
}

#[test]
fn an_entry_already_there_writes_nothing() {
    let value = json!({ "command": "/bin/devflow", "args": ["mcp"] });
    let text = json!({ "mcpServers": { "devflow": value } }).to_string();
    assert_eq!(put(Some(&text), "mcpServers", &value).unwrap(), None);
}

#[test]
fn a_config_with_comments_is_left_as_it_is() {
    let text = "{\n  // mine\n  \"servers\": {}\n}";
    assert!(put(Some(text), "servers", &json!({})).is_err());
}

#[test]
fn a_missing_config_is_made() {
    let new = put(None, "servers", &json!({ "type": "stdio" }))
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&new).unwrap()["servers"]["devflow"]["type"],
        "stdio"
    );
}

#[test]
fn removing_takes_only_devflows_entry() {
    let text = r#"{"mcp":{"devflow":{},"other":{}}}"#;
    let new = drop(Some(text), "mcp").unwrap().unwrap();
    let doc: Value = serde_json::from_str(&new).unwrap();
    assert!(doc["mcp"].get("devflow").is_none());
    assert!(doc["mcp"].get("other").is_some());
    assert_eq!(drop(Some(&new), "mcp").unwrap(), None);
}

#[test]
fn a_dry_run_writes_nothing_and_a_real_one_keeps_a_copy() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(".cursor/mcp.json");
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(&file, r#"{"mcpServers":{}}"#).unwrap();
    let step = register(Tool::Cursor, "/bin/devflow", &machine(dir.path(), None)).remove(0);

    assert!(carry(&step, true).unwrap().starts_with("would add"));
    assert_eq!(fs::read_to_string(&file).unwrap(), r#"{"mcpServers":{}}"#);

    carry(&step, false).unwrap();
    assert_eq!(
        fs::read_to_string(backup_of(&file)).unwrap(),
        r#"{"mcpServers":{}}"#
    );
    assert!(fs::read_to_string(&file).unwrap().contains("/bin/devflow"));
    assert!(carry(&step, false).unwrap().starts_with("ok:"));
}

#[test]
fn a_cli_that_already_has_devflow_is_not_asked_again() {
    let dir = tempfile::tempdir().unwrap();
    let said = Some("devflow  devflow@devflow  enabled");
    let steps = register(Tool::Claude, "devflow", &machine(dir.path(), said));
    assert!(steps.iter().all(|step| matches!(step, Step::Done(_))));

    let steps = register(Tool::Codex, "/bin/devflow", &machine(dir.path(), None));
    assert_eq!(
        steps,
        vec![Step::Run(
            [
                "codex",
                "mcp",
                "add",
                "devflow",
                "--",
                "/bin/devflow",
                "mcp"
            ]
            .map(str::to_owned)
            .to_vec()
        )]
    );
}

#[test]
fn opencode_in_jsonc_is_left_to_the_person() {
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join(".config/opencode");
    fs::create_dir_all(&folder).unwrap();
    fs::write(folder.join("opencode.jsonc"), "{}").unwrap();
    let steps = register(Tool::OpenCode, "/bin/devflow", &machine(dir.path(), None));
    assert!(matches!(steps[0], Step::Manual(_)));
}

#[test]
fn tools_are_named_or_found() {
    let dir = tempfile::tempdir().unwrap();
    let here = machine(dir.path(), None);
    assert_eq!(
        chosen(Some("codex, cursor"), &here).unwrap(),
        vec![Tool::Codex, Tool::Cursor]
    );
    assert!(chosen(Some("emacs"), &here).is_err());
    assert_eq!(chosen(None, &here).unwrap().len(), ALL.len());
}
