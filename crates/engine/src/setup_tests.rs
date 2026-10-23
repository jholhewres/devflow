use super::*;
use crate::config::{Check, Report};

fn with_checks(runs: &[(&str, &str)]) -> Config {
    let mut config = Config::default();
    config.stages.execution.checks = runs
        .iter()
        .map(|(name, run)| Check {
            name: (*name).into(),
            run: (*run).into(),
            report: Report::Nothing,
            evidence: Vec::new(),
            requires: None,
            exclusive: None,
        })
        .collect();
    config
}

fn changes_of(done: &[FileChange]) -> Vec<(&str, &str)> {
    done.iter()
        .map(|one| (one.path.as_str(), one.change))
        .collect()
}

#[test]
fn each_command_moves_into_a_script_that_says_where_it_came_from() {
    let config = with_checks(&[("unit", "make test"), ("lint", &script_run("lint"))]);
    let sources = [("make test".to_owned(), "Makefile:4".to_owned())];
    let (config, scripts) = scripted(config, &sources);
    assert_eq!(
        config.stages.execution.checks[0].run,
        "sh .devpit/devflow/scripts/check-unit.sh"
    );
    // Already a script of its own: left as it is.
    assert_eq!(scripts.len(), 1);
    let text = script_text(&scripts[0]);
    assert!(text.starts_with("#!/bin/sh\n"), "{text}");
    assert!(text.contains("found in Makefile:4"), "{text}");
    assert!(text.ends_with("\nmake test\n"), "{text}");
}

#[test]
fn a_setup_writes_the_folder_and_nothing_before_it_is_asked() {
    let root = tempfile::tempdir().expect("tempdir");
    let (config, scripts) = scripted(with_checks(&[("unit", "make test")]), &[]);
    let files = planned(&crate::render::render(&config), &scripts, None);

    let previewed = preview(root.path(), &files);
    assert!(previewed.iter().all(|one| one.change == "create"));
    assert!(!root.path().join(".devpit").exists());

    let done = write(root.path(), &files).expect("written");
    assert_eq!(
        changes_of(&done),
        [
            (".devpit/devflow/devflow.yaml", "create"),
            (".devpit/devflow/.gitignore", "create"),
            (".devpit/devflow/scripts/check-unit.sh", "create"),
        ]
    );
    // The personas and the schema are devpit's: read from it, never copied.
    assert!(!root.path().join(".devpit/devflow/reviewers").exists());
    assert!(!root
        .path()
        .join(".devpit/devflow/devflow-findings.schema.json")
        .exists());
    let ignore =
        std::fs::read_to_string(root.path().join(".devpit/devflow/.gitignore")).expect("gitignore");
    assert!(ignore.lines().any(|line| line == "runs/"), "{ignore}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(root.path().join(".devpit/devflow/scripts/check-unit.sh"))
            .expect("script")
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0o111);
    }

    // Again: nothing to do, and the person's own ignores stay.
    std::fs::write(root.path().join(".devpit/devflow/.gitignore"), "*.log").expect("edit");
    let again = write(root.path(), &files).expect("again");
    let said = changes_of(&again);
    assert_eq!(said[0], (".devpit/devflow/devflow.yaml", "same"));
    assert_eq!(said[1], (".devpit/devflow/.gitignore", "append"));
    assert_eq!(
        std::fs::read_to_string(root.path().join(".devpit/devflow/.gitignore")).expect("read"),
        "*.log\nruns/\n"
    );
}

#[test]
fn a_script_no_check_runs_is_listed_and_removed_only_when_devpit_wrote_it_as_it_is() {
    let root = tempfile::tempdir().expect("tempdir");
    let scripts = root.path().join(".devpit/devflow/scripts");
    std::fs::create_dir_all(&scripts).expect("scripts");
    let written = |name: &str, command: &str, source: Option<&str>| {
        script_text(&Script {
            name: name.into(),
            command: command.into(),
            source: source.map(str::to_owned),
        })
    };
    std::fs::write(
        scripts.join("check-old.sh"),
        written("old", "make old", Some("Makefile:2")),
    )
    .expect("old");
    std::fs::write(scripts.join("check-bare.sh"), written("bare", "true", None)).expect("bare");
    let edited = format!("{}make more\n", written("mine", "make mine", None));
    std::fs::write(scripts.join("check-mine.sh"), edited).expect("mine");
    std::fs::write(scripts.join("notes.txt"), "not a check").expect("notes");
    let (config, scripts_now) = scripted(with_checks(&[("unit", "make test")]), &[]);
    let files = with_unused(
        root.path(),
        &config,
        planned(&crate::render::render(&config), &scripts_now, None),
    );

    let said = preview(root.path(), &files);
    let unused: Vec<(&str, &str)> = changes_of(&said)
        .into_iter()
        .filter(|(path, _)| !path.ends_with("check-unit.sh") && path.contains("/scripts/"))
        .collect();
    assert_eq!(
        unused,
        [
            (".devpit/devflow/scripts/check-bare.sh", "remove"),
            (".devpit/devflow/scripts/check-mine.sh", "unused"),
            (".devpit/devflow/scripts/check-old.sh", "remove"),
        ]
    );
    assert!(
        scripts.join("check-old.sh").is_file(),
        "a preview removes nothing"
    );

    write(root.path(), &files).expect("written");
    assert!(!scripts.join("check-old.sh").exists());
    assert!(!scripts.join("check-bare.sh").exists());
    assert!(scripts.join("check-mine.sh").is_file());
    assert!(scripts.join("check-unit.sh").is_file());
    assert!(scripts.join("notes.txt").is_file());
}

#[test]
fn every_persona_devpit_ships_is_known_as_shipped() {
    // Changing a persona's text? Add its new SHA-256 to SHIPPED, so the
    // copies older setups made of it keep reading devpit's.
    for (name, text) in PERSONAS {
        assert!(shipped(name, text), "{name} is not in SHIPPED");
        assert!(
            shipped(name, &text.replace('\n', "\r\n")),
            "{name} with CRLF"
        );
        assert!(!shipped(name, &format!("{text}\nOne line of ours.\n")));
    }
    assert!(
        !shipped("devflow-all", PERSONAS[0].1),
        "another persona's text"
    );
}

#[cfg(unix)]
#[test]
fn a_folder_that_leads_outside_the_project_is_refused() {
    let root = tempfile::tempdir().expect("root");
    let elsewhere = tempfile::tempdir().expect("elsewhere");
    std::os::unix::fs::symlink(elsewhere.path(), root.path().join(".devpit")).expect("link");
    let files = config_only("version: 1\n", &[]);
    assert!(write(root.path(), &files).is_err());
    assert!(std::fs::read_dir(elsewhere.path())
        .expect("read")
        .next()
        .is_none());
}
