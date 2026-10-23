//! vitest's `--reporter=json`, which is jest's shape.

use std::path::Path;

use crate::verdict::{FailedTest, Tested};
use serde::Deserialize;

use super::{Outcome, Reported};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Report {
    num_passed_tests: u32,
    num_failed_tests: u32,
    #[serde(default)]
    num_pending_tests: u32,
    #[serde(default)]
    num_todo_tests: u32,
    test_results: Vec<File>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct File {
    name: String,
    status: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    assertion_results: Vec<Assertion>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Assertion {
    full_name: String,
    status: String,
    #[serde(default)]
    failure_messages: Vec<String>,
}

pub(super) fn from_json(text: &str, cwd: &Path) -> Option<Reported> {
    let report: Report = serde_json::from_str(text).ok()?;
    let mut reported = Reported::of(Tested {
        passed: report.num_passed_tests,
        failed: report.num_failed_tests,
        skipped: report.num_pending_tests + report.num_todo_tests,
        read_from: vec!["vitest".to_owned()],
        ..Tested::default()
    });
    for file in &report.test_results {
        let place = Some(super::relative(&file.name, cwd));
        for test in &file.assertion_results {
            let outcome = match test.status.as_str() {
                "passed" => Outcome::Passed,
                "failed" => Outcome::Failed,
                _ => Outcome::Skipped,
            };
            reported.case(&test.full_name, place.clone(), outcome);
        }
    }
    let tested = &mut reported.tested;
    for file in &report.test_results {
        let failures: Vec<FailedTest> = file
            .assertion_results
            .iter()
            .filter(|test| test.status == "failed")
            .map(|test| FailedTest {
                name: test.full_name.clone(),
                file: Some(super::relative(&file.name, cwd)),
                message: test.failure_messages.first().and_then(|m| super::short(m)),
            })
            .collect();
        // A failed file with no failed test never ran (import error, hook):
        // it is in no count, so it counts as one failure.
        if failures.is_empty() && file.status == "failed" {
            tested.failed += 1;
            tested.failures.push(FailedTest {
                name: "the whole file".to_owned(),
                file: Some(super::relative(&file.name, cwd)),
                message: super::short(&file.message),
            });
        }
        tested.failures.extend(failures);
    }
    tested.failures.truncate(crate::verdict::MOST_FAILURES_KEPT);
    Some(reported)
}
