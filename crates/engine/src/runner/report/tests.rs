//! Each format against recorded reports (paths moved under `/work/app`).

use std::path::Path;

use super::*;

const CWD: &str = "/work/app";

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!("../../../fixtures/reports/", $name))
    };
}

fn file(text: &str) -> Tested {
    from_file(text, Path::new(CWD)).expect("a report it recognises")
}

fn printed(text: &str) -> Option<Tested> {
    read(None, Some(text), Path::new(CWD))
}

#[test]
fn vitest_that_passed_counts_every_test() {
    let tested = file(fixture!("vitest-passed.json"));
    assert_eq!((tested.passed, tested.failed), (2, 0));
    assert_eq!(tested.read_from, ["vitest"]);
}

#[test]
fn vitest_that_failed_names_the_test_its_file_and_why() {
    let tested = file(fixture!("vitest-failed.json"));
    assert_eq!((tested.passed, tested.failed, tested.skipped), (1, 1, 1));
    let failure = &tested.failures[0];
    assert_eq!(failure.name, "the answer is wrong");
    assert_eq!(failure.file.as_deref(), Some("src/fail.test.ts"));
    assert_eq!(
        failure.message.as_deref(),
        Some("AssertionError: expected 41 to be 42 // Object.is equality")
    );
}

#[test]
fn a_vitest_file_that_never_ran_is_a_failure() {
    let tested = file(fixture!("vitest-broken-file.json"));
    assert_eq!((tested.passed, tested.failed), (2, 1));
    assert_eq!(
        tested.failures[0].file.as_deref(),
        Some("src/broken.test.ts")
    );
    assert!(tested.failures[0]
        .message
        .as_deref()
        .is_some_and(|said| said.starts_with("Cannot find module")));
}

#[test]
fn vitest_that_matched_nothing_reports_nothing_passed() {
    let tested = file(fixture!("vitest-none.json"));
    assert_eq!((tested.passed, tested.failed), (0, 0));
}

#[test]
fn cargo_test_that_passed_counts_every_binary() {
    let tested = printed(fixture!("cargo-passed.txt")).expect("a result line");
    assert_eq!((tested.passed, tested.failed, tested.skipped), (2, 0, 1));
    assert_eq!(tested.read_from, ["cargo test"]);
}

#[test]
fn cargo_test_that_failed_says_where_it_panicked() {
    let tested = printed(fixture!("cargo-failed.txt")).expect("a result line");
    assert_eq!((tested.passed, tested.failed, tested.skipped), (1, 1, 1));
    let failure = &tested.failures[0];
    assert_eq!(failure.name, "tests::the_answer_is_wrong");
    assert_eq!(failure.file.as_deref(), Some("src/lib.rs"));
    assert_eq!(
        failure.message.as_deref(),
        Some("assertion `left == right` failed: off by one")
    );
}

#[test]
fn cargo_test_that_matched_nothing_reports_nothing_passed() {
    let tested = printed(fixture!("cargo-none.txt")).expect("a result line");
    assert_eq!((tested.passed, tested.failed), (0, 0));
}

#[test]
fn libtest_json_reads_like_its_text() {
    let tested = printed(fixture!("libtest-failed.jsonl")).expect("a suite line");
    assert_eq!((tested.passed, tested.failed, tested.skipped), (1, 1, 1));
    assert_eq!(tested.failures[0].name, "tests::the_answer_is_wrong");
    assert_eq!(tested.failures[0].file.as_deref(), Some("src/lib.rs"));
}

/// A subtest counts and its parent does not; a package that never built fails.
#[test]
fn go_test_json_counts_each_test_once_and_a_package_that_did_not_build() {
    let text = fixture!("go-failed.jsonl");
    for tested in [printed(text).expect("go events"), file(text)] {
        assert_eq!((tested.passed, tested.failed, tested.skipped), (1, 2, 1));
        assert_eq!(tested.read_from, ["go test"]);
        let failure = &tested.failures[0];
        assert_eq!(failure.name, "TestRename/empty_title");
        assert_eq!(failure.file.as_deref(), Some("rename_test.go"));
        assert_eq!(
            failure.message.as_deref(),
            Some("expected an error, got none")
        );
        assert_eq!(tested.failures[1].name, "example.com/broken");
        assert_eq!(tested.failures[1].file.as_deref(), Some("broken.go"));
    }
    let cases = cases_printed(text);
    assert_eq!(outcome_of("TestRename", &cases), Some(Outcome::Failed));
    assert_eq!(outcome_of("TestAdds", &cases), Some(Outcome::Passed));
    // Lines that are not go's events are not read as them.
    assert!(printed(fixture!("libtest-failed.jsonl"))
        .is_some_and(|tested| tested.read_from == ["cargo test"]));
}

/// A parent that fails on its own, its subtests green, is still a failure.
#[test]
fn a_go_test_that_failed_after_its_subtests_passed_failed() {
    let event = |action: &str, test: &str| {
        format!(r#"{{"Action":"{action}","Package":"example.com/cards","Test":"{test}"}}"#)
    };
    let text = [
        event("pass", "TestRename/a"),
        event("fail", "TestRename"),
        r#"{"Action":"fail","Package":"example.com/cards"}"#.to_owned(),
    ]
    .join("\n");
    let tested = printed(&text).expect("go events");
    assert_eq!((tested.passed, tested.failed), (1, 1));
    assert_eq!(tested.failures[0].name, "TestRename");
}

#[test]
fn pytest_junit_counts_failures_errors_and_skips() {
    let tested = file(fixture!("pytest-failed.xml"));
    assert_eq!((tested.passed, tested.failed, tested.skipped), (1, 2, 1));
    assert_eq!(tested.read_from, ["JUnit"]);
    assert_eq!(tested.failures[0].name, "test_the_answer_is_wrong");
    assert_eq!(
        tested.failures[0].message.as_deref(),
        Some("AssertionError: off by one")
    );
}

#[test]
fn pytest_junit_that_passed_and_that_matched_nothing() {
    let passed = file(fixture!("pytest-passed.xml"));
    assert_eq!((passed.passed, passed.failed), (1, 0));
    let none = file(fixture!("pytest-none.xml"));
    assert_eq!((none.passed, none.failed), (0, 0));
}

#[test]
fn node_junit_reads_the_same_way() {
    let failed = file(fixture!("node-failed.xml"));
    assert_eq!((failed.passed, failed.failed), (1, 1));
    assert_eq!(failed.failures[0].message.as_deref(), Some("41 == 42"));
    let passed = file(fixture!("node-passed.xml"));
    assert_eq!((passed.passed, passed.failed), (1, 0));
}

#[test]
fn an_output_that_was_cut_is_not_read() {
    assert_eq!(read(None, None, Path::new(CWD)), None);
}

#[test]
fn output_with_no_result_line_reports_nothing() {
    assert_eq!(printed("error[E0425]: cannot find value `x`\n"), None);
}

#[test]
fn every_report_in_the_folder_adds_up_with_what_was_printed() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("web.json"), fixture!("vitest-failed.json")).unwrap();
    std::fs::write(dir.path().join("py.xml"), fixture!("pytest-passed.xml")).unwrap();
    std::fs::write(dir.path().join("notes.txt"), "not a report").unwrap();

    let tested = read(
        Some(dir.path()),
        Some(fixture!("cargo-passed.txt")),
        Path::new(CWD),
    )
    .expect("three reports");
    assert_eq!((tested.passed, tested.failed), (1 + 1 + 2, 1));
    assert_eq!(tested.read_from, ["JUnit", "vitest", "cargo test"]);
}

#[test]
fn a_report_past_the_ceiling_is_not_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let big = std::fs::File::create(dir.path().join("big.json")).unwrap();
    big.set_len(MOST_REPORT + 1).unwrap();
    assert_eq!(read(Some(dir.path()), None, Path::new(CWD)), None);
}

#[cfg(unix)]
#[test]
fn a_link_in_the_folder_is_not_followed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("tempdir");
    let target = outside.path().join("report.json");
    std::fs::write(&target, fixture!("vitest-passed.json")).unwrap();
    std::os::unix::fs::symlink(&target, dir.path().join("report.json")).unwrap();
    assert_eq!(read(Some(dir.path()), None, Path::new(CWD)), None);
}

#[test]
fn a_long_message_is_cut_and_loses_its_colour() {
    let said = short(&format!("\u{1b}[31m{}\u{1b}[39m\nmore", "x".repeat(400))).unwrap();
    assert!(said.starts_with("xxx") && said.ends_with('…'));
    assert_eq!(said.chars().count(), LONGEST_MESSAGE + 1);
}

fn ended(cases: &[Case]) -> Vec<(&str, Outcome)> {
    cases
        .iter()
        .map(|case| (case.name.as_str(), case.outcome))
        .collect()
}

fn cases_in(text: &str) -> Vec<Case> {
    file_cases(text, Path::new(CWD))
        .expect("a report it recognises")
        .cases
}

fn cases_printed(text: &str) -> Vec<Case> {
    read_cases(None, Some(text), Path::new(CWD))
        .expect("a result line")
        .cases
}

#[test]
fn each_test_a_report_names_is_kept_with_how_it_ended() {
    use Outcome::{Failed, Passed, Skipped};
    let junit = cases_in(fixture!("pytest-failed.xml"));
    assert_eq!(
        ended(&junit),
        [
            ("test_adds", Passed),
            ("test_the_answer_is_wrong", Failed),
            ("test_later", Skipped),
            ("test_errors", Failed)
        ]
    );
    assert_eq!(junit[0].place.as_deref(), Some("test_sample"));
    assert_eq!(
        ended(&cases_in(fixture!("vitest-failed.json"))),
        [
            ("adds", Passed),
            ("the answer is wrong", Failed),
            ("later", Skipped)
        ]
    );
    let cargo = [
        ("tests::later", Skipped),
        ("tests::adds", Passed),
        ("tests::the_answer_is_wrong", Failed),
    ];
    assert_eq!(ended(&cases_printed(fixture!("cargo-failed.txt"))), cargo);
    assert_eq!(
        ended(&cases_printed(fixture!("libtest-failed.jsonl"))),
        cargo
    );
}

#[test]
fn a_test_is_named_by_its_whole_path_or_by_its_last_parts() {
    let cargo = cases_printed(fixture!("cargo-failed.txt"));
    assert_eq!(outcome_of("tests::adds", &cargo), Some(Outcome::Passed));
    assert_eq!(outcome_of("adds", &cargo), Some(Outcome::Passed));
    assert_eq!(
        outcome_of("my_crate::tests::adds", &cargo),
        Some(Outcome::Passed)
    );
    assert_eq!(
        outcome_of("the_answer_is_wrong", &cargo),
        Some(Outcome::Failed)
    );
    // Only at a separator: `dds` is not `adds`.
    assert_eq!(outcome_of("dds", &cargo), None);
    assert_eq!(outcome_of("tests::missing", &cargo), None);
    let pytest = cases_in(fixture!("pytest-failed.xml"));
    assert_eq!(
        outcome_of("tests/test_sample.py::test_adds", &pytest),
        Some(Outcome::Passed)
    );
    assert_eq!(outcome_of("test_later", &pytest), Some(Outcome::Skipped));
}

#[test]
fn a_test_that_failed_anywhere_failed() {
    let cases = [Outcome::Passed, Outcome::Failed, Outcome::Skipped].map(|outcome| Case {
        name: "renames".into(),
        place: None,
        outcome,
    });
    assert_eq!(outcome_of("renames", &cases), Some(Outcome::Failed));
    assert_eq!(outcome_of("renames", &cases[..1]), Some(Outcome::Passed));
    assert_eq!(outcome_of("renames", &cases[2..]), Some(Outcome::Skipped));
}

#[test]
fn a_parameterized_test_is_named_by_the_test_every_run_belongs_to() {
    // The first run passed and the second failed.
    let runs = |[first, second]: [&str; 2]| {
        [(first, Outcome::Passed), (second, Outcome::Failed)].map(|(name, outcome)| Case {
            name: name.into(),
            place: None,
            outcome,
        })
    };
    for (named, cases) in [
        (
            "testRename",
            runs([
                "testRename with data set #0",
                "testRename with data set \"empty\"",
            ]),
        ),
        (
            "it renames",
            runs(["it renames with ('a')", "it renames with ('')"]),
        ),
        (
            "tests/test_cli.py::test_rename",
            runs(["test_rename[a-b]", "test_rename[]"]),
        ),
        (
            "TestRename",
            runs(["TestRename/a", "TestRename/empty_title"]),
        ),
    ] {
        assert_eq!(outcome_of(named, &cases), Some(Outcome::Failed), "{named}");
        assert_eq!(
            outcome_of(named, &cases[..1]),
            Some(Outcome::Passed),
            "{named}"
        );
        assert_eq!(outcome_of(&cases[0].name, &cases), Some(Outcome::Passed));
    }
    // A test whose name only starts the same is another test.
    let other = runs(["test_rename_twice[a]", "TestRenameAll/a"]);
    assert_eq!(outcome_of("test_rename", &other), None);
    assert_eq!(outcome_of("TestRename", &other), None);
    // A slash outside a Go test is part of its name.
    assert_eq!(cases::base("renames a/b"), None);
}
