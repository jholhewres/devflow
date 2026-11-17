use std::fs;
use std::process::Command;

fn devflow(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_devflow"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn the_help_names_the_flow_and_its_commands() {
    let out = devflow(&["--help"]);
    let said = String::from_utf8(out.stdout).unwrap();

    assert!(out.status.success());
    assert!(said.contains("evidence-gated"));
    assert!(said.contains("status"));
}

#[test]
fn a_project_without_a_configuration_exits_one() {
    let dir = tempfile::tempdir().unwrap();
    let out = devflow(&["status", "--root", dir.path().to_str().unwrap()]);

    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stdout)
        .unwrap()
        .starts_with("No configuration"));
}

#[test]
fn a_project_with_one_names_its_file() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("devflow.yaml"), "version: 2\n").unwrap();
    let out = devflow(&["status", "--root", dir.path().to_str().unwrap()]);

    assert!(out.status.success());
    assert!(String::from_utf8(out.stdout)
        .unwrap()
        .contains("devflow.yaml"));
}

#[test]
fn the_status_lists_each_stages_model_and_where_it_came_from() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("devflow.yaml"),
        "version: 2\nstages:\n  - uses: builtin/plan\n    model: large\n  - uses: builtin/execution\n",
    )
    .unwrap();
    let out = devflow(&["status", "--root", dir.path().to_str().unwrap()]);
    let said = String::from_utf8(out.stdout).unwrap();
    assert!(out.status.success(), "{said}");
    let line = |stage: &str| {
        said.lines()
            .find(|line| line.trim_start().starts_with(stage))
            .unwrap_or_else(|| panic!("no {stage} line in:\n{said}"))
            .split_whitespace()
            .collect::<Vec<_>>()
    };
    assert!(said.contains("Models (preset economy"), "{said}");
    assert_eq!(line("plan"), ["plan", "large", "(opus)", "stage"]);
    assert_eq!(
        line("execution"),
        ["execution", "small", "(sonnet)", "preset"]
    );
    assert_eq!(line("briefing"), ["briefing", "-", "default"]);
}

#[test]
fn a_tier_a_cli_has_no_model_for_says_it_runs_on_that_clis_default() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("devflow.yaml"),
        "version: 2\nreview:\n  reviewers:\n    - { agent: codex, persona: devflow-spec, model: large }\n",
    )
    .unwrap();
    let out = devflow(&["status", "--root", dir.path().to_str().unwrap()]);
    let said = String::from_utf8(out.stdout).unwrap();
    let row = said
        .lines()
        .find(|line| line.contains("[codex devflow-spec]"))
        .unwrap_or_else(|| panic!("no codex row in:\n{said}"));
    assert!(row.contains("large (the CLI's default)"), "{row}");
    assert!(said.contains("the session on claude"), "{said}");
}

#[test]
fn a_model_that_reads_as_a_flag_gets_devflows_own_refusal() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("devflow.yaml"), "version: 2\n").unwrap();
    let out = devflow(&[
        "config",
        "set",
        "stages.execution.model",
        "-x",
        "--root",
        dir.path().to_str().unwrap(),
    ]);
    let said = String::from_utf8(out.stderr).unwrap();
    assert_eq!(out.status.code(), Some(1), "{said}");
    assert!(said.contains("`-x` is not a model"), "{said}");
}
