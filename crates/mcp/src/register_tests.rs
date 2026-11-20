use std::fs;

use super::*;

fn machine(home: &Path, said: Option<&'static str>) -> Machine {
    Machine {
        home: home.to_path_buf(),
        config: home.join(".config"),
        claude: home.to_path_buf(),
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
    claude_user_config(dir.path(), json!({ "command": "devflow", "args": ["mcp"] }));
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

#[test]
fn a_tool_is_registered_once_every_step_is_done() {
    let home = tempfile::tempdir().unwrap();
    let machine = machine(home.path(), None);
    assert!(!registered(Tool::Cursor, "/bin/devflow", &machine));
    fs::create_dir_all(home.path().join(".cursor")).unwrap();
    let value = json!({ "command": "/bin/devflow", "args": ["mcp"] });
    fs::write(
        home.path().join(".cursor/mcp.json"),
        json!({ "mcpServers": { "devflow": value } }).to_string(),
    )
    .unwrap();
    assert!(registered(Tool::Cursor, "/bin/devflow", &machine));
    assert!(!registered(Tool::Cursor, "/other/devflow", &machine));
    let said = machine_saying(home.path(), "devflow devflow@devflow");
    assert!(
        !registered(Tool::Claude, "/bin/devflow", &said),
        "the plugin alone is not enough: its server is hidden by another plugin named devflow"
    );
    claude_user_config(
        home.path(),
        json!({ "command": "devflow", "args": ["mcp"] }),
    );
    assert!(registered(Tool::Claude, "/bin/devflow", &said));
}

/// Claude Code's `.claude.json` under `dir`, with the person's own server and
/// `devflow` as given.
fn claude_user_config(dir: &Path, devflow: Value) {
    let doc = json!({
        "numStartups": 3,
        "mcpServers": { "theirs": { "type": "stdio", "command": "theirs", "args": [] }, "devflow": devflow },
        "projects": {},
    });
    fs::write(dir.join(".claude.json"), doc.to_string()).unwrap();
}

fn argv(words: &[&str]) -> Step {
    Step::Run(words.iter().map(|word| (*word).to_owned()).collect())
}

#[test]
fn claudes_user_config_runs_the_server_as_the_plugin_names_it() {
    // Claude Code keeps one of two servers that run the same command and
    // arguments, so the entry must be the plugin manifest's, word for word.
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.claude-plugin/plugin.json");
    let manifest: Value = serde_json::from_str(&fs::read_to_string(manifest).unwrap()).unwrap();
    let server = &manifest["mcpServers"]["devflow"];
    assert_eq!(server["command"], CLAUDE_SERVER[0]);
    assert_eq!(server["args"], json!(CLAUDE_SERVER[1..]));

    let home = tempfile::tempdir().unwrap();
    let plugin_only = machine_saying(home.path(), "devflow  devflow@devflow  enabled");
    let steps = register(Tool::Claude, "/home/me/.local/bin/devflow", &plugin_only);
    assert_eq!(
        steps.last(),
        Some(&argv(&[
            "claude", "mcp", "add", "--scope", "user", "devflow", "--", "devflow", "mcp"
        ])),
        "named bare, as the plugin names it, never the binary's whole path: {steps:?}"
    );
}

#[test]
fn the_user_configs_devflow_server_is_read_for_what_it_runs() {
    let home = tempfile::tempdir().unwrap();
    assert_eq!(user_server(home.path()), UserServer::Missing);
    fs::write(home.path().join(".claude.json"), "{ not json").unwrap();
    assert_eq!(user_server(home.path()), UserServer::Missing);
    // Its own variables do not matter: Claude Code compares the command.
    claude_user_config(
        home.path(),
        json!({ "type": "stdio", "command": "devflow", "args": ["mcp"], "env": { "DEVFLOW_NO_UPDATE": "1" } }),
    );
    assert_eq!(user_server(home.path()), UserServer::Same);
    claude_user_config(
        home.path(),
        json!({ "command": "/opt/devflow/bin/devflow", "args": ["mcp"] }),
    );
    assert_eq!(
        user_server(home.path()),
        UserServer::Other("/opt/devflow/bin/devflow mcp".to_owned())
    );
    claude_user_config(
        home.path(),
        json!({ "type": "http", "url": "https://example.test/mcp" }),
    );
    assert_eq!(
        user_server(home.path()),
        UserServer::Other("a http server".to_owned())
    );
}

#[test]
fn another_devflow_server_in_the_user_config_is_replaced_and_one_there_is_left() {
    let add = argv(&[
        "claude", "mcp", "add", "--scope", "user", "devflow", "--", "devflow", "mcp",
    ]);
    let remove = argv(&["claude", "mcp", "remove", "--scope", "user", "devflow"]);
    assert_eq!(claude_server(&UserServer::Missing), vec![add.clone()]);
    assert_eq!(
        claude_server(&UserServer::Other("/opt/devflow mcp".to_owned())),
        vec![remove, add]
    );
    assert!(matches!(
        claude_server(&UserServer::Same)[..],
        [Step::Done(_)]
    ));
}

#[test]
fn taking_devflow_out_of_claude_removes_its_user_server_only_when_there() {
    let home = tempfile::tempdir().unwrap();
    let machine = machine(home.path(), None);
    let remove = argv(&["claude", "mcp", "remove", "--scope", "user", "devflow"]);
    assert!(!unregister(Tool::Claude, &machine).contains(&remove));
    claude_user_config(
        home.path(),
        json!({ "command": "devflow", "args": ["mcp"] }),
    );
    assert_eq!(unregister(Tool::Claude, &machine)[0], remove);
}

fn machine_saying(home: &Path, said: &'static str) -> Machine {
    machine(home, Some(said))
}
