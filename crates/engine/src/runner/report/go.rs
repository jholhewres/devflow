//! `go test -json`: one event per line, a test's last one `pass`, `fail` or
//! `skip`, its `output` lines before it.

use std::collections::{HashMap, HashSet};

use crate::verdict::{FailedTest, Tested};
use serde::Deserialize;

use super::{Outcome, Reported};

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Event {
    action: String,
    #[serde(default)]
    package: String,
    #[serde(default)]
    test: String,
    #[serde(default)]
    output: String,
}

/// The events' tests, or `None` when no line is one of `go test -json`'s.
pub(super) fn from_lines(text: &str) -> Option<Reported> {
    let mut tested = Tested {
        read_from: vec!["go test".to_owned()],
        ..Tested::default()
    };
    let mut cases = Reported::default();
    let mut said: HashMap<(String, String), String> = HashMap::new();
    let mut failed_in: Vec<String> = Vec::new();
    let mut parents: HashSet<(String, String)> = HashSet::new();
    let mut failed_under: HashSet<(String, String)> = HashSet::new();
    let mut any = false;
    for line in text.lines().filter(|line| line.starts_with('{')) {
        let Ok(event) = serde_json::from_str::<Event>(line) else {
            continue;
        };
        any = true;
        let ended = match event.action.as_str() {
            "pass" => Outcome::Passed,
            "fail" => Outcome::Failed,
            "skip" => Outcome::Skipped,
            "output" => {
                let kept = said.entry((event.package, event.test)).or_default();
                if kept.len() < 4096 {
                    kept.push_str(&event.output);
                }
                continue;
            }
            _ => continue,
        };
        let key = (event.package, event.test);
        let output = said.remove(&key);
        let (package, test) = &key;
        if test.is_empty() {
            // A package that failed with no test failing did not build.
            if ended == Outcome::Failed && !failed_in.contains(package) {
                tested.failed += 1;
                failed(&mut tested, package, output.as_deref());
            }
            continue;
        }
        // A test with subtests ends after them and is counted by them, unless
        // it failed with every subtest green.
        let by_subtests = if ended == Outcome::Failed {
            &failed_under
        } else {
            &parents
        };
        if by_subtests.contains(&key) {
            continue;
        }
        for (at, _) in test.match_indices('/') {
            let parent = (package.clone(), test[..at].to_owned());
            if ended == Outcome::Failed {
                failed_under.insert(parent.clone());
            }
            parents.insert(parent);
        }
        match ended {
            Outcome::Passed => tested.passed += 1,
            Outcome::Failed => tested.failed += 1,
            Outcome::Skipped => tested.skipped += 1,
        }
        cases.case(test, (!package.is_empty()).then(|| package.clone()), ended);
        if ended == Outcome::Failed {
            failed_in.push(package.clone());
            failed(&mut tested, test, output.as_deref());
        }
    }
    if !any {
        return None;
    }
    cases.tested = tested;
    Some(cases)
}

/// Keeps a failure, with the `file.go:12: message` line its output names.
fn failed(tested: &mut Tested, name: &str, output: Option<&str>) {
    if tested.failures.len() >= crate::verdict::MOST_FAILURES_KEPT {
        return;
    }
    let output = output.unwrap_or_default();
    let line = output.lines().map(str::trim).find(|line| {
        line.split(':')
            .next()
            .is_some_and(|file| file.ends_with(".go"))
    });
    let (file, message) = match line.and_then(|line| line.split_once(": ")) {
        Some((at, message)) => (
            at.split(':').next().map(str::to_owned),
            super::short(message),
        ),
        None => (None, super::short(output)),
    };
    tested.failures.push(FailedTest {
        name: name.to_owned(),
        file,
        message,
    });
}
