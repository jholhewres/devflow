use std::fs;
use std::path::PathBuf;

use super::*;

fn machine(home: &Path) -> Machine {
    Machine {
        home: home.to_path_buf(),
        config: home.join(".config"),
        claude: home.to_path_buf(),
        codex: home.join(".codex"),
        project: None,
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
fn doctor_says_which_devflow_it_is_first() {
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
    assert!(said[0].ok);
    assert_eq!(
        said[0].what,
        format!("devflow {}", env!("CARGO_PKG_VERSION"))
    );
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

#[test]
fn a_budget_the_old_question_prefilled_is_pointed_out_with_how_to_take_it_out() {
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let folder = root.path().join(".devflow");
    fs::create_dir_all(&folder).unwrap();
    fs::write(
        folder.join("devflow.yaml"),
        "version: 2\nenabled: true\nstages:\n  attack:\n    run: release\n    budget: { run_usd: 5, month_usd: 50 }\n",
    )
    .unwrap();
    let consent = Consent::at(&home.path().join("devflow"));
    let said = findings(
        root.path(),
        &machine(home.path()),
        &consent,
        "/bin/devflow",
        &[],
    );
    assert!(
        !said
            .iter()
            .any(|one| one.what.contains("stages.attack.budget")),
        "written by hand: theirs"
    );

    let parts = ["run_usd".to_owned(), "month_usd".to_owned()];
    consent
        .keep_answer(
            &Project::at(root.path()).root,
            &crate::consent::Answered {
                switched_on: true,
                targets: None,
                yeses: &["enabled"],
                parts: &parts,
                how: crate::consent::How::Elicitation,
                asked_for: "attack",
                at: std::time::SystemTime::now(),
            },
        )
        .unwrap();
    let said = findings(
        root.path(),
        &machine(home.path()),
        &consent,
        "/bin/devflow",
        &[],
    );
    let budget = said
        .iter()
        .find(|one| one.what.contains("stages.attack.budget"))
        .expect("pointed out");
    assert!(budget.optional, "{}", budget.what);
    assert!(
        budget.what.contains("US$ 5 per attack, US$ 50 a month"),
        "{}",
        budget.what
    );
    assert!(
        budget
            .what
            .contains("devflow config set stages.attack.budget null"),
        "{}",
        budget.what
    );
}

#[test]
fn an_attack_with_no_sandbox_here_is_said_to_run_its_exploits_in_the_session() {
    let attack = devflow_engine::config::Attack::default();
    let said = sandbox(&attack, std::ffi::OsStr::new(""));
    assert!(!said.ok && said.optional, "{}", said.what);
    assert!(said.what.contains("no sandbox here"), "{}", said.what);
    assert!(
        said.what.contains("the session runs each exploit"),
        "{}",
        said.what
    );
}

#[cfg(unix)]
#[test]
fn a_php_project_left_on_php_8_is_told_its_image_has_no_mbstring() {
    use std::os::unix::fs::PermissionsExt;
    let bin = tempfile::tempdir().unwrap();
    let docker = bin.path().join("docker");
    fs::write(&docker, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).unwrap();
    let attack = devflow_engine::config::Attack {
        sandbox: Some(devflow_engine::config::SandboxChoice::Docker),
        image: Some("php:8".to_owned()),
        test: Some("vendor/bin/phpunit \"$DEVFLOW_EXPLOIT\"".to_owned()),
        ..Default::default()
    };
    let said = sandbox(&attack, bin.path().as_os_str());
    assert!(!said.ok && said.optional, "{}", said.what);
    assert!(
        said.what
            .contains("devflow config set stages.attack.image composer:2"),
        "{}",
        said.what
    );
    let fine = devflow_engine::config::Attack {
        image: Some("composer:2".to_owned()),
        ..attack
    };
    assert!(sandbox(&fine, bin.path().as_os_str()).ok);
}

#[test]
fn the_persons_yeses_and_what_is_not_asked_again_are_listed() {
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let consent = Consent::at(&home.path().join("devflow"));
    assert!(consented(root.path(), &consent).is_empty());
    let parts = [
        "test".to_owned(),
        "sandbox".to_owned(),
        "run_usd".to_owned(),
        "targets:sha256:00".to_owned(),
    ];
    consent
        .keep_answer(
            &Project::at(root.path()).root,
            &crate::consent::Answered {
                switched_on: true,
                targets: None,
                yeses: &["enabled", "stages.attack"],
                parts: &parts,
                how: crate::consent::How::Elicitation,
                asked_for: "attack",
                at: std::time::SystemTime::UNIX_EPOCH
                    + std::time::Duration::from_secs(1_795_000_000),
            },
        )
        .unwrap();
    let said = consented(root.path(), &consent);
    assert!(said.iter().all(|one| one.ok));
    assert!(
        said[0]
            .what
            .contains("enabled to the client's question at 2026"),
        "{}",
        said[0].what
    );
    assert!(said[0].what.contains("(for attack)"), "{}", said[0].what);
    assert!(
        said[1]
            .what
            .contains("does not ask again for: targets, test "),
        "{}",
        said[1].what
    );
    assert!(
        !said[1].what.contains("run_usd") && !said[1].what.contains("sandbox"),
        "{}",
        said[1].what
    );
    assert!(
        said[1].what.contains("devflow setup --attack"),
        "{}",
        said[1].what
    );
}

#[test]
fn an_update_lock_left_behind_is_pointed_out() {
    let dir = tempfile::tempdir().unwrap();
    let lock = dir.path().join("update.lock");
    assert!(update_lock(&lock).is_none());
    fs::write(&lock, std::process::id().to_string()).unwrap();
    assert!(update_lock(&lock).unwrap().ok, "held by a live update");
    let mut ended = std::process::Command::new("true").spawn().unwrap();
    let gone = ended.id();
    ended.wait().unwrap();
    fs::write(&lock, gone.to_string()).unwrap();
    let said = update_lock(&lock).unwrap();
    assert!(
        said.optional && said.what.contains("takes it over"),
        "{}",
        said.what
    );
}

/// The newest attack whose exploits failed on their environment, several of
/// them, is pointed out with the command detected from the project's own
/// Makefile, its Go build tags in it; one alone is not.
#[test]
fn an_attack_whose_exploits_failed_on_their_environment_is_pointed_out() {
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let folder = root.path().join(".devflow");
    fs::create_dir_all(folder.join("runs")).unwrap();
    fs::write(
        folder.join("devflow.yaml"),
        "version: 2\nenabled: true\nstages:\n  attack:\n    run: release\n    test: go test ./...\n",
    )
    .unwrap();
    fs::write(root.path().join("go.mod"), "module x\n").unwrap();
    fs::write(
        root.path().join("Makefile"),
        "test:\n\tgo test -tags sqlite_fts5 ./...\n",
    )
    .unwrap();
    let ledger = folder
        .join("runs")
        .join(devflow_engine::attack_metrics::LEDGER);
    let line = |run: &str, errors: u64| {
        serde_json::json!({ "item": "card_1", "run": run,
            "metrics": { "env_error": errors, "env_repeated": errors } })
        .to_string()
    };
    fs::write(&ledger, format!("{}\n", line("20261123T000000Z", 1))).unwrap();
    let consent = Consent::at(&home.path().join("devflow"));
    let said = |root: &Path| findings(root, &machine(home.path()), &consent, "/bin/devflow", &[]);
    assert!(!said(root.path())
        .iter()
        .any(|one| one.what.contains("env_error")));
    fs::write(
        &ledger,
        format!(
            "{}\n{}\n",
            line("20261123T000000Z", 1),
            line("20261123T010000Z", 3)
        ),
    )
    .unwrap();
    let found = said(root.path());
    let warned = found
        .iter()
        .find(|one| one.what.contains("env_error"))
        .expect("pointed out");
    assert!(warned.optional, "{}", warned.what);
    assert!(
        warned
            .what
            .contains("(run 20261123T010000Z of card_1): 3 exploits"),
        "{}",
        warned.what
    );
    assert!(
        warned
            .what
            .contains("devflow config set stages.attack.test 'd=$(dirname"),
        "{}",
        warned.what
    );
    assert!(
        warned.what.contains("&& go test -tags sqlite_fts5 -v -run"),
        "{}",
        warned.what
    );
    assert!(
        warned.what.contains("(as Makefile:2 runs them)"),
        "{}",
        warned.what
    );
    // The command set is already the one detected: the session runs them.
    let detected = devflow_engine::detect::exploit_test_at(
        root.path(),
        &devflow_engine::detect::detected(root.path(), crate::flow::setup::machine(root.path())),
    )
    .expect("go")
    .command;
    fs::write(
        folder.join("devflow.yaml"),
        format!(
            "version: 2\nenabled: true\nstages:\n  attack:\n    run: release\n    test: {}\n",
            serde_json::to_string(&detected).unwrap()
        ),
    )
    .unwrap();
    let found = said(root.path());
    let warned = found
        .iter()
        .find(|one| one.what.contains("env_error"))
        .expect("pointed out");
    assert!(
        warned.what.contains("run each exploit in the session"),
        "{}",
        warned.what
    );
}

/// One exploit that could not run and holds the item is pointed out too,
/// saying it holds; below `block_on` they are a warning.
#[test]
fn an_attack_that_could_not_run_and_holds_the_item_is_pointed_out() {
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let folder = root.path().join(".devflow");
    fs::create_dir_all(folder.join("runs")).unwrap();
    fs::write(
        folder.join("devflow.yaml"),
        "version: 2\nenabled: true\nstages:\n  attack:\n    run: release\n    test: go test ./...\n",
    )
    .unwrap();
    fs::write(
        folder
            .join("runs")
            .join(devflow_engine::attack_metrics::LEDGER),
        format!(
            "{}\n",
            serde_json::json!({ "item": "card_1", "run": "20261123T000000Z",
                "metrics": { "env_error": 1, "env_repeated": 1, "env_held": 1 } })
        ),
    )
    .unwrap();
    let consent = Consent::at(&home.path().join("devflow"));
    let said = findings(
        root.path(),
        &machine(home.path()),
        &consent,
        "/bin/devflow",
        &[],
    );
    let warned = said
        .iter()
        .find(|one| one.what.contains("env_error"))
        .expect("pointed out");
    assert!(
        warned
            .what
            .contains("1 that could not run hold the item at the gate"),
        "{}",
        warned.what
    );
}
