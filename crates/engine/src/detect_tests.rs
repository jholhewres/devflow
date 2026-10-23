use super::*;

fn project(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    for (name, body) in files {
        let path = dir.path().join(name);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("folder");
        std::fs::write(path, body).expect("write");
    }
    dir
}

fn cli(name: Agent, installed: bool, signed_in: Option<bool>) -> Cli {
    Cli {
        name,
        installed,
        signed_in,
    }
}

#[test]
fn a_makefile_target_is_found_with_its_line_and_settles_the_choice() {
    let dir = project(&[
        (
            "Makefile",
            "build:\n\tcargo build\n\ntest: build\n\tcargo test\nlint:\n\tcargo clippy\n",
        ),
        ("Cargo.toml", "[package]\nname = \"x\"\n"),
    ]);
    let found = detected(dir.path(), Machine::default());
    assert_eq!(found.test[0].command, "make test");
    assert_eq!(found.test[0].source, "Makefile:4");
    assert_eq!(found.test[1].command, "cargo test");
    assert_eq!(found.lint[0].source, "Makefile:6");
    assert!(open(&found).is_empty(), "{:?}", open(&found));
}

/// `go test -json` is read test by test, so a Go check is more than its exit code.
#[test]
fn a_go_module_tests_with_go_test_json_into_the_report_folder() {
    let dir = project(&[("go.mod", "module example.com/cards\n")]);
    let found = detected(dir.path(), Machine::default());
    assert_eq!(found.test[0].report, Report::Go);
    assert!(
        found.test[0]
            .command
            .starts_with("go test -json ./... > \"$DEVFLOW_REPORT_DIR/"),
        "{}",
        found.test[0].command
    );
    assert_eq!(found.lint[0].command, "go vet ./...");
}

#[test]
fn two_test_commands_without_a_makefile_are_left_to_the_person() {
    let dir = project(&[
        (
            "package.json",
            "{\n  \"scripts\": {\n    \"test\": \"node t.js\"\n  }\n}\n",
        ),
        (
            "composer.json",
            "{\n  \"require-dev\": {\n    \"phpunit/phpunit\": \"^11\"\n  }\n}\n",
        ),
    ]);
    let found = detected(dir.path(), Machine::default());
    let said = open(&found);
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(said[0].contains("npm test (package.json:3)"), "{said:?}");
    assert!(said[0].contains("composer.json:3"), "{said:?}");
}

#[test]
fn an_e2e_tool_nothing_runs_is_an_open_decision() {
    let dir = project(&[
        ("playwright.config.ts", "export default {}\n"),
        ("Makefile", "test:\n\tpytest\n"),
    ]);
    let found = detected(dir.path(), Machine::default());
    assert_eq!(found.e2e_tools[0].name, "playwright");
    assert!(open(&found)
        .iter()
        .any(|one| one.contains("playwright.config.ts") && one.contains("no command")));
}

#[test]
fn nothing_found_says_so() {
    let dir = project(&[]);
    let found = detected(dir.path(), Machine::default());
    assert_eq!(open(&found), ["no test command was found"]);
}

#[test]
fn a_cli_signed_out_and_a_project_opted_out_are_asked_about() {
    let dir = project(&[("Makefile", "test:\n\ttrue\n")]);
    let found = detected(
        dir.path(),
        Machine {
            clis: vec![
                cli(Agent::Claude, true, Some(true)),
                cli(Agent::Codex, true, Some(false)),
                cli(Agent::Gemini, true, None),
                cli(Agent::Cursor, false, None),
            ],
            decisions_key: true,
            decisions_opted_out: true,
            ..Machine::default()
        },
    );
    let said = open(&found);
    assert_eq!(said.len(), 2, "{said:?}");
    assert!(said[0].starts_with("codex is installed but not signed in"));
    assert!(said[1].contains("opted out"));
}

#[test]
fn a_manifest_outside_the_project_is_not_read() {
    let outside = project(&[("Makefile", "test:\n\ttrue\n")]);
    let dir = project(&[]);
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path().join("Makefile"), dir.path().join("Makefile"))
        .expect("link");
    let found = detected(dir.path(), Machine::default());
    assert!(found.test.is_empty(), "{:?}", found.test);
}

#[test]
fn the_repositorys_own_flow_comes_back_as_hints() {
    let dir = project(&[
        ("AGENTS.md", "# Agents\n"),
        ("CONTRIBUTING.md", "# Contributing\n"),
        (".github/pull_request_template.md", "## What\n"),
        (".github/ISSUE_TEMPLATE/bug.md", "## Bug\n"),
        (".claude/skills/ticket/SKILL.md", "---\nname: ticket\n---\n"),
    ]);
    let machine = Machine {
        branches: vec![
            "main".into(),
            "develop".into(),
            "feature/LED-1-x".into(),
            "spike".into(),
        ],
        subjects: vec![
            "LED-123 Fix the login".into(),
            "Merge LED-99 and OPS-7".into(),
            "Bump to v1.2-3".into(),
            "LED-1: tidy".into(),
        ],
        installed_skills: vec!["deploy".into()],
        ..Machine::default()
    };
    let hints = detected(dir.path(), machine).hints;
    assert_eq!(hints.guides, ["AGENTS.md", "CONTRIBUTING.md"]);
    assert_eq!(hints.pr_templates, [".github/pull_request_template.md"]);
    assert_eq!(hints.issue_templates, [".github/ISSUE_TEMPLATE/bug.md"]);
    assert_eq!(hints.branches, ["develop", "feature/LED-1-x"]);
    assert_eq!(hints.ticket_keys, ["LED", "OPS"]);
    assert_eq!(hints.skills, ["deploy", "ticket"]);
    // Without develop beside them, feature branches are not git-flow.
    let plain = Machine {
        branches: vec!["main".into(), "feature/x".into()],
        ..Machine::default()
    };
    assert!(detected(dir.path(), plain).hints.branches.is_empty());
}

/// A file counts under the spelling its folder lists, so a case-insensitive
/// disk does not report one template under two names.
#[test]
fn a_file_counts_only_under_its_own_spelling() {
    let dir = project(&[
        (".github/pull_request_template.md", "## What\n"),
        ("AGENTS.md", "# A\n"),
    ]);
    assert!(spelled_as(dir.path(), ".github/pull_request_template.md"));
    assert!(!spelled_as(dir.path(), ".github/PULL_REQUEST_TEMPLATE.md"));
    assert!(spelled_as(dir.path(), "AGENTS.md"));
    assert!(!spelled_as(dir.path(), "agents.md"));
}

/// `go test ./...` at the root stops at a module's edge.
#[test]
fn a_go_module_in_a_subfolder_becomes_a_check_of_its_own() {
    let dir = project(&[
        ("Makefile", "test:\n\ttrue\n"),
        ("services/api/go.mod", "module example.com/api\n"),
        ("node_modules/x/go.mod", "module example.com/x\n"),
        ("a/b/c/go.mod", "module example.com/c\n"),
    ]);
    let found = detected(dir.path(), Machine::default());
    let folders: Vec<&str> = found.nested.iter().map(|one| one.folder.as_str()).collect();
    assert_eq!(folders, ["services/api"]);
    let checks = crate::preset::checks(&found);
    let api = checks
        .iter()
        .find(|one| one.name == "unit-services-api")
        .expect("unit-services-api");
    assert!(
        api.run.starts_with("go -C services/api test -json ./..."),
        "{}",
        api.run
    );
    assert_eq!(api.source.as_deref(), Some("services/api/go.mod:1"));
}

#[test]
fn typescript_with_a_tsconfig_and_no_typecheck_script_is_checked_by_tsc() {
    let package = "{\n  \"devDependencies\": {\n    \"typescript\": \"^5\"\n  }\n}\n";
    let dir = project(&[("package.json", package), ("tsconfig.json", "{}")]);
    let found = detected(dir.path(), Machine::default());
    let checks = crate::preset::checks(&found);
    let typecheck = checks
        .iter()
        .find(|one| one.name == "typecheck")
        .expect("typecheck");
    assert_eq!(typecheck.run, "npx tsc --noEmit");
    assert_eq!(typecheck.source.as_deref(), Some("package.json:3"));

    let scripted = "{\n  \"scripts\": { \"typecheck\": \"vue-tsc\" },\n  \"devDependencies\": { \"typescript\": \"^5\" }\n}\n";
    let dir = project(&[("package.json", scripted), ("tsconfig.json", "{}")]);
    assert!(detected(dir.path(), Machine::default())
        .typecheck
        .is_empty());
}
