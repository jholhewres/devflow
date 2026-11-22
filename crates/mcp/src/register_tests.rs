use std::fs;

use super::*;

fn machine(home: &Path, said: Option<&'static str>) -> Machine {
    Machine {
        home: home.to_path_buf(),
        config: home.join(".config"),
        claude: home.to_path_buf(),
        codex: home.join(".codex"),
        project: None,
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
        steps[0],
        Step::Run(
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
        )
    );
    assert!(matches!(
        steps[1],
        Step::Toml {
            key: "tool_timeout_sec",
            ..
        }
    ));
    assert!(matches!(steps[2], Step::Hook { .. }));
    assert_eq!(steps.len(), 3, "no project, no AGENTS.md");
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
    assert!(
        !registered(Tool::Cursor, "/bin/devflow", &machine),
        "the server alone: its gate hook is missing"
    );
    fs::write(
        home.path().join(".cursor/hooks.json"),
        json!({ "version": 1, "hooks": { "stop": [
            { "command": "/bin/devflow hook stop --agent cursor", "loop_limit": 5 }
        ] } })
        .to_string(),
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

#[test]
fn a_hook_is_added_beside_the_persons_and_an_older_one_of_devflows_replaced() {
    let mine = json!({ "command": "./audit.sh" });
    let old = json!({ "command": "/old/devflow hook stop --agent cursor", "loop_limit": 5 });
    let text = json!({ "hooks": { "stop": [mine, old] } }).to_string();
    let entry = json!({ "command": "/bin/devflow hook stop --agent cursor", "loop_limit": 5 });
    let top = ("version", json!(1));
    let new = hook_put(Some(&text), ["hooks", "stop"], &entry, Some(&top))
        .unwrap()
        .unwrap();
    let doc: Value = serde_json::from_str(&new).unwrap();
    assert_eq!(doc["version"], 1);
    assert_eq!(doc["hooks"]["stop"], json!([mine, entry]));
    assert_eq!(
        hook_put(Some(&new), ["hooks", "stop"], &entry, Some(&top)).unwrap(),
        None,
        "there already"
    );
    let dropped = hook_drop(Some(&new), ["hooks", "stop"]).unwrap().unwrap();
    let doc: Value = serde_json::from_str(&dropped).unwrap();
    assert_eq!(doc["hooks"]["stop"], json!([mine]));
    assert_eq!(hook_drop(Some(&dropped), ["hooks", "stop"]).unwrap(), None);
    // Codex's shape: the command one level down.
    let codex = json!({ "hooks": [{ "type": "command", "command": "/bin/devflow hook stop --agent codex" }] });
    let made = hook_put(None, ["hooks", "Stop"], &codex, None)
        .unwrap()
        .unwrap();
    let gone = hook_drop(Some(&made), ["hooks", "Stop"]).unwrap().unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&gone).unwrap(),
        json!({ "hooks": {} })
    );
    assert!(hook_put(Some("{ // mine\n }"), ["hooks", "stop"], &entry, None).is_err());
}

#[test]
fn a_toml_table_gets_one_line_and_keeps_the_rest_as_written() {
    let text = "# my settings\nmodel = \"o3\"\n\n[mcp_servers.devflow]\ncommand = \"/bin/devflow\"\nargs = [\"mcp\"]\n\n[mcp_servers.other] # mine\ncommand = \"x\"\n";
    let new = toml_set(text, "mcp_servers.devflow", "tool_timeout_sec", "3600")
        .unwrap()
        .unwrap();
    assert_eq!(
        new,
        "# my settings\nmodel = \"o3\"\n\n[mcp_servers.devflow]\ntool_timeout_sec = 3600\ncommand = \"/bin/devflow\"\nargs = [\"mcp\"]\n\n[mcp_servers.other] # mine\ncommand = \"x\"\n"
    );
    assert_eq!(
        toml_set(&new, "mcp_servers.devflow", "tool_timeout_sec", "3600").unwrap(),
        None
    );
    let theirs = new.replace("tool_timeout_sec = 3600", "tool_timeout_sec = 120");
    assert_eq!(
        toml_set(&theirs, "mcp_servers.devflow", "tool_timeout_sec", "3600").unwrap(),
        None,
        "the person's own value stands"
    );
    assert!(toml_set(
        "model = 1\n",
        "mcp_servers.devflow",
        "tool_timeout_sec",
        "3600"
    )
    .is_err());
}

#[test]
fn devflows_section_of_agents_md_is_added_replaced_and_taken_out_alone() {
    let mine = "# Agents\n\nUse pnpm.\n";
    let with = block_put(Some(mine), "devflow v1").unwrap();
    assert!(with
        .starts_with("# Agents\n\nUse pnpm.\n\n<!-- devflow -->\ndevflow v1\n<!-- /devflow -->"));
    assert_eq!(block_put(Some(&with), "devflow v1"), None);
    let newer = block_put(Some(&with), "devflow v2").unwrap();
    assert!(newer.contains("devflow v2") && !newer.contains("devflow v1"));
    assert_eq!(block_drop(&newer).unwrap(), mine);
    assert_eq!(block_drop(mine), None);
    assert_eq!(
        block_put(None, "devflow v1").unwrap(),
        "<!-- devflow -->\ndevflow v1\n<!-- /devflow -->\n"
    );
}

#[test]
fn a_project_gets_cursors_rule_and_agents_md_and_unregister_takes_only_devflows() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let mut machine = machine(home.path(), None);
    machine.project = Some(project.path().to_path_buf());
    for step in register(Tool::Cursor, "/bin/devflow", &machine)
        .iter()
        .chain(&register(Tool::Codex, "/bin/devflow", &machine))
    {
        if matches!(step, Step::Run(_) | Step::Toml { .. }) {
            continue;
        }
        let said = carry(step, true).unwrap();
        assert!(said.starts_with("would "), "{said}");
        carry(step, false).unwrap();
    }
    let rule = project.path().join(".cursor/rules/devflow.mdc");
    assert_eq!(fs::read_to_string(&rule).unwrap(), CURSOR_RULE);
    let agents = fs::read_to_string(project.path().join("AGENTS.md")).unwrap();
    assert!(agents.contains("<!-- devflow -->"), "{agents}");
    assert!(hook_installed(Tool::Cursor, "/bin/devflow", &machine) == Some(true));
    assert!(hook_installed(Tool::Codex, "/bin/devflow", &machine) == Some(true));
    assert_eq!(
        hook_installed(Tool::Antigravity, "/bin/devflow", &machine),
        None
    );
    // A rule the person changed is theirs: unregister leaves it.
    fs::write(&rule, "mine now").unwrap();
    for step in unregister(Tool::Cursor, &machine)
        .iter()
        .chain(&unregister(Tool::Codex, &machine))
    {
        if !matches!(step, Step::Run(_)) {
            carry(step, false).unwrap();
        }
    }
    assert_eq!(fs::read_to_string(&rule).unwrap(), "mine now");
    assert!(
        !project.path().join("AGENTS.md").exists(),
        "it held only devflow's"
    );
    assert!(hook_installed(Tool::Cursor, "/bin/devflow", &machine) == Some(false));
}

#[test]
fn cursor_is_not_found_by_a_folder_an_uninstall_left() {
    let home = tempfile::tempdir().unwrap();
    let nothing = Machine {
        has: Box::new(|_| false),
        ..machine(home.path(), None)
    };
    fs::create_dir_all(home.path().join(".cursor")).unwrap();
    assert!(!nothing.found(Tool::Cursor), "a folder alone");
    fs::write(home.path().join(".cursor/mcp.json"), "{}").unwrap();
    assert!(nothing.found(Tool::Cursor), "a config Cursor reads");
    let cli = Machine {
        has: Box::new(|program| program == "cursor-agent"),
        ..machine(home.path(), None)
    };
    assert!(cli.found(Tool::Cursor));
}

#[test]
fn antigravity_and_windsurf_get_the_server_where_each_reads_it() {
    let home = tempfile::tempdir().unwrap();
    let nothing = Machine {
        has: Box::new(|_| false),
        ..machine(home.path(), None)
    };
    assert!(!nothing.found(Tool::Antigravity) && !nothing.found(Tool::Windsurf));
    fs::create_dir_all(home.path().join(".gemini/antigravity")).unwrap();
    fs::write(home.path().join(".gemini/antigravity/installation_id"), "x").unwrap();
    assert!(nothing.found(Tool::Antigravity));
    let value = json!({ "command": "/bin/devflow", "args": ["mcp"] });
    assert_eq!(
        register(Tool::Antigravity, "/bin/devflow", &nothing),
        vec![Step::Put {
            file: home.path().join(".gemini/config/mcp_config.json"),
            under: "mcpServers",
            value: value.clone(),
        }]
    );
    // Windsurf's own file, or Devin Desktop's, the app Windsurf became.
    let file = |machine: &Machine| match &register(Tool::Windsurf, "/bin/devflow", machine)[0] {
        Step::Put { file, .. } => file.clone(),
        other => panic!("{other:?}"),
    };
    assert_eq!(
        file(&nothing),
        home.path().join(".codeium/windsurf/mcp_config.json")
    );
    let devin = Machine {
        has: Box::new(|program| program == "devin-desktop"),
        ..machine(home.path(), None)
    };
    assert!(devin.found(Tool::Windsurf));
    assert_eq!(
        file(&devin),
        home.path().join(".config/devin/mcp_config.json")
    );
    for step in register(Tool::Antigravity, "/bin/devflow", &nothing) {
        carry(&step, false).unwrap();
    }
    assert!(registered(Tool::Antigravity, "/bin/devflow", &nothing));
    for step in unregister(Tool::Antigravity, &nothing) {
        carry(&step, false).unwrap();
    }
    assert!(!registered(Tool::Antigravity, "/bin/devflow", &nothing));
}

#[test]
fn a_toml_line_keeps_crlf_a_quoted_key_and_a_commented_header() {
    let crlf = "[mcp_servers.devflow] # mine\r\ncommand = \"devflow\"\r\n";
    let new = toml_set(crlf, "mcp_servers.devflow", "tool_timeout_sec", "3600")
        .unwrap()
        .unwrap();
    assert_eq!(
        new,
        "[mcp_servers.devflow] # mine\r\ntool_timeout_sec = 3600\r\ncommand = \"devflow\"\r\n"
    );
    let quoted = "[mcp_servers.devflow]\n\"tool_timeout_sec\" = 60\n";
    assert_eq!(
        toml_set(quoted, "mcp_servers.devflow", "tool_timeout_sec", "3600").unwrap(),
        None
    );
}

#[test]
fn an_end_marker_before_devflows_section_is_the_persons_text() {
    let said = "see <!-- /devflow --> above\n\n<!-- devflow -->\nold\n<!-- /devflow -->\n";
    let new = block_put(Some(said), "new").unwrap();
    assert_eq!(
        new,
        "see <!-- /devflow --> above\n\n<!-- devflow -->\nnew\n<!-- /devflow -->\n"
    );
    assert_eq!(block_put(Some(&new), "new"), None);
    assert_eq!(block_drop(&new).unwrap(), "see <!-- /devflow --> above\n");
}

#[cfg(unix)]
#[test]
fn a_config_behind_a_link_is_written_where_the_link_points() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("dotfiles/mcp.json");
    fs::create_dir_all(real.parent().unwrap()).unwrap();
    fs::write(&real, "{}").unwrap();
    let link = dir.path().join("mcp.json");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let step = Step::Put {
        file: link.clone(),
        under: "mcpServers",
        value: json!({ "command": "/bin/devflow" }),
    };
    carry(&step, false).unwrap();
    assert!(fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(fs::read_to_string(&real).unwrap().contains("devflow"));
}
