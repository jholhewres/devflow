use super::*;
use crate::detect::{detected, open, Machine};

fn project(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    for (name, body) in files {
        let path = dir.path().join(name);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("folder");
        std::fs::write(path, body).expect("write");
    }
    dir
}

/// The machine with the `PATH` this test runs with, as a check's shell has it.
fn here() -> Machine {
    Machine {
        path: std::env::var_os("PATH"),
        ..Machine::default()
    }
}

/// A phpstan nobody installed, behind `make lint`: the target is there, its
/// recipe cannot run.
#[test]
fn a_make_lint_whose_first_command_is_missing_is_unavailable_and_not_recommended() {
    let dir = project(&[(
        "Makefile",
        "test:\n\ttrue\nlint:\n\t@echo linting\n\tdevpit-no-such-linter analyse src\n",
    )]);
    let found = detected(dir.path(), here());
    let why = found.lint[0].unavailable.as_deref().expect("unavailable");
    assert!(why.contains("devpit-no-such-linter"), "{why}");
    assert_eq!(found.test[0].unavailable, None);
    let names: Vec<String> = crate::preset::checks(&found)
        .into_iter()
        .map(|one| one.name)
        .collect();
    assert_eq!(names, ["unit"]);
    assert!(
        open(&found)
            .iter()
            .any(|one| one.contains("`make lint` (Makefile:3) cannot run here")),
        "{:?}",
        open(&found)
    );
}

#[test]
fn a_program_in_the_projects_own_vendor_bin_is_found() {
    let dir = project(&[
        ("Makefile", "lint:\n\tphpstan analyse\n"),
        ("vendor/bin/phpstan", "#!/bin/sh\n"),
    ]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let script = dir.path().join("vendor/bin/phpstan");
        std::fs::set_permissions(script, std::fs::Permissions::from_mode(0o755)).expect("mode");
    }
    let found = detected(dir.path(), here());
    assert_eq!(found.lint[0].unavailable, None);
}

#[test]
fn a_command_not_installed_is_unavailable_without_validation_it_is_not() {
    let dir = project(&[("composer.json", "{ \"scripts\": { \"lint\": \"x\" } }")]);
    let path = OsString::from("/devpit-no-such-folder");
    let why = why_not(dir.path(), &path, "composer lint").expect("unavailable");
    assert!(why.contains("`composer`"), "{why}");
    let unvalidated = detected(dir.path(), Machine::default());
    assert_eq!(unvalidated.lint[0].unavailable, None);
}

#[test]
fn the_program_a_line_starts_is_told_only_when_it_can_be() {
    assert_eq!(first_program("FOO=1 phpstan analyse"), Some("phpstan"));
    assert_eq!(
        first_program("vendor/bin/phpunit --log-junit x"),
        Some("vendor/bin/phpunit")
    );
    assert_eq!(first_program("cd web && npm test"), None);
    assert_eq!(first_program("make[1]: Entering directory '/x'"), None);
    assert_eq!(first_program("make: Nothing to be done for 'lint'."), None);
    assert_eq!(first_program("$(BIN)/lint"), None);
    assert_eq!(make_target("make lint"), Some("lint"));
    assert_eq!(make_target("make -C web lint"), None);
    assert_eq!(make_target("cargo test"), None);
}
