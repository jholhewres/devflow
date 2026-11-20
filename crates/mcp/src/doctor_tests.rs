use std::fs;
use std::path::PathBuf;

use super::*;

fn machine(home: &Path) -> Machine {
    Machine {
        home: home.to_path_buf(),
        config: home.join(".config"),
        claude: home.to_path_buf(),
        mac: false,
        has: Box::new(|_| false),
        ask: Box::new(|_| None),
    }
}

#[test]
fn a_project_without_devflow_is_told_how_to_set_it_up() {
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let consent = Consent::at(&home.path().join("devflow"));
    let said = findings(
        root.path(),
        &machine(home.path()),
        &consent,
        "/bin/devflow",
        &[],
    );
    assert!(said
        .iter()
        .any(|one| !one.ok && one.what.contains("no agent CLI or IDE found")));
    assert!(said
        .iter()
        .any(|one| one.optional && one.what.contains("`devflow setup`")));
}

#[test]
fn a_set_up_project_says_whether_it_is_on_and_its_runs_are_ignored() {
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let folder: PathBuf = root.path().join(".devflow");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("devflow.yaml"), "version: 2\nenabled: true\n").unwrap();
    let consent = Consent::at(&home.path().join("devflow"));
    let said = findings(
        root.path(),
        &machine(home.path()),
        &consent,
        "/bin/devflow",
        &[],
    );
    assert!(said
        .iter()
        .any(|one| !one.ok && one.what.contains("devflow is not on here")));
    assert!(said
        .iter()
        .any(|one| !one.ok && one.what.contains("does not ignore runs/")));
    consent.remember(root.path(), Ask::Enable, true).unwrap();
    std::fs::write(folder.join(".gitignore"), "runs/\n").unwrap();
    let said = findings(
        root.path(),
        &machine(home.path()),
        &consent,
        "/bin/devflow",
        &[],
    );
    assert!(said
        .iter()
        .any(|one| one.ok && one.what == "devflow is on here"));
    assert!(said
        .iter()
        .any(|one| one.ok && one.what.contains("kept out of git")));
}

/// devpit's `enabled: true` is its own switch: devflow's, kept on this
/// machine, is said apart, with the question and the one command that
/// switch it on.
#[test]
fn the_files_switch_and_devflows_own_are_told_apart() {
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let folder: PathBuf = root.path().join(".devpit/devflow");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("devflow.yaml"), "version: 2\nenabled: true\n").unwrap();
    let consent = Consent::at(&home.path().join("devflow"));
    let said = findings(
        root.path(),
        &machine(home.path()),
        &consent,
        "/bin/devflow",
        &[],
    );
    let off = said
        .iter()
        .find(|one| !one.ok && one.what.contains("devflow is not on here"))
        .expect("said off");
    for part in [
        "enabled: true",
        "on this machine",
        "asks you",
        "`devflow setup --attack`",
    ] {
        assert!(off.what.contains(part), "{part}: {}", off.what);
    }
    std::fs::write(folder.join("devflow.yaml"), "version: 2\nenabled: false\n").unwrap();
    consent.remember(root.path(), Ask::Enable, true).unwrap();
    let said = findings(
        root.path(),
        &machine(home.path()),
        &consent,
        "/bin/devflow",
        &[],
    );
    assert!(said
        .iter()
        .any(|one| !one.ok && one.what.contains("says `enabled: false`")));
}

/// A plugin folder named `name`, with skills only, or with devflow's server
/// too.
fn plugin(dir: &Path, name: &str, serves: bool) {
    fs::create_dir_all(dir.join(".claude-plugin")).unwrap();
    fs::create_dir_all(dir.join("skills/plan")).unwrap();
    fs::write(dir.join("skills/plan/SKILL.md"), "---\nname: plan\n---\n").unwrap();
    let mut manifest = serde_json::json!({ "name": name, "version": "0.0.1" });
    if serves {
        manifest["mcpServers"] =
            serde_json::json!({ "devflow": { "command": "devflow", "args": ["mcp"] } });
    }
    fs::write(dir.join(".claude-plugin/plugin.json"), manifest.to_string()).unwrap();
}

fn session(words: &[&str]) -> Vec<Vec<String>> {
    vec![
        vec!["/bin/sh".to_owned(), "-c".to_owned()],
        words.iter().map(|word| (*word).to_owned()).collect(),
    ]
}

/// Claude installed, with the devflow plugin; its user config holding
/// `devflow`, or nothing.
fn with_claude(home: &Path, devflow: Option<serde_json::Value>) -> Machine {
    let servers = devflow.map_or_else(
        || serde_json::json!({}),
        |devflow| serde_json::json!({ "devflow": devflow }),
    );
    fs::write(
        home.join(".claude.json"),
        serde_json::json!({ "mcpServers": servers }).to_string(),
    )
    .unwrap();
    Machine {
        has: Box::new(|program| program == "claude"),
        ask: Box::new(|_| Some("devflow  devflow@devflow  enabled".to_owned())),
        ..machine(home)
    }
}

#[test]
fn a_session_that_loads_another_plugin_named_devflow_is_told_how_to_have_devflow_anyway() {
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let theirs = home.path().join("their-plugin");
    plugin(&theirs, "devflow", false);
    let consent = Consent::at(&home.path().join("devflow"));
    let flag = format!("--plugin-dir={}", theirs.display());
    let words = session(&[
        "claude",
        "--permission-mode",
        "default",
        &flag,
        "--name",
        "x",
    ]);

    let said = findings(
        root.path(),
        &with_claude(home.path(), None),
        &consent,
        "/bin/devflow",
        &words,
    );
    let hidden = said
        .iter()
        .find(|one| one.what.contains(&theirs.display().to_string()))
        .expect("the plugin that hides devflow's is named");
    assert!(!hidden.ok, "{}", hidden.what);
    assert!(hidden.what.contains(CLAUDE_FIX), "{}", hidden.what);
    let claude = said
        .iter()
        .find(|one| one.what.starts_with("claude:"))
        .unwrap();
    assert!(!claude.ok && !claude.optional, "{}", claude.what);
    assert!(
        claude.what.contains("--plugin-dir") && claude.what.contains(CLAUDE_FIX),
        "{}",
        claude.what
    );

    // With the server in the user config, the session has it.
    let same =
        serde_json::json!({ "type": "stdio", "command": "devflow", "args": ["mcp"], "env": {} });
    let said = findings(
        root.path(),
        &with_claude(home.path(), Some(same)),
        &consent,
        "/bin/devflow",
        &words,
    );
    assert!(said
        .iter()
        .filter(|one| one.what.starts_with("claude:")
            || one.what.starts_with("this Claude Code session"))
        .all(|one| one.ok));
}

#[test]
fn a_devflow_server_that_runs_something_else_is_said_to_show_each_tool_twice() {
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let consent = Consent::at(&home.path().join("devflow"));
    let other = serde_json::json!({ "command": "/opt/bin/devflow", "args": ["mcp"] });
    let said = findings(
        root.path(),
        &with_claude(home.path(), Some(other)),
        &consent,
        "/bin/devflow",
        &[],
    );
    let claude = said
        .iter()
        .find(|one| one.what.starts_with("claude:"))
        .unwrap();
    assert!(!claude.ok, "{}", claude.what);
    assert!(
        claude.what.contains("/opt/bin/devflow mcp") && claude.what.contains("twice"),
        "{}",
        claude.what
    );
}

#[test]
fn only_a_plugin_named_devflow_without_its_server_hides_devflow() {
    let dir = tempfile::tempdir().unwrap();
    let theirs = dir.path().join("theirs");
    let checkout = dir.path().join("checkout");
    let other = dir.path().join("other");
    let in_file = dir.path().join("in-file");
    plugin(&theirs, "devflow", false);
    plugin(&checkout, "devflow", true);
    plugin(&other, "devpit", false);
    plugin(&in_file, "devflow", false);
    fs::write(
        in_file.join(".mcp.json"),
        r#"{ "devflow": { "command": "devflow", "args": ["mcp"] } }"#,
    )
    .unwrap();
    let at = |dir: &Path| dir.display().to_string();

    assert_eq!(
        shadowing(&session(&["claude", "--plugin-dir", &at(&theirs)])),
        Some(theirs.clone())
    );
    assert_eq!(
        shadowing(&session(&[
            "claude",
            &format!("--plugin-dir={}", at(&theirs))
        ])),
        Some(theirs)
    );
    for hides_nothing in [&checkout, &other, &in_file] {
        assert_eq!(
            shadowing(&session(&["claude", "--plugin-dir", &at(hides_nothing)])),
            None
        );
    }
    assert_eq!(
        shadowing(&session(&["claude", "--plugin-dir", "/no/such/folder"])),
        None
    );
    assert_eq!(shadowing(&session(&["claude", "--plugin-dir"])), None);
    assert_eq!(shadowing(&[]), None);
}
