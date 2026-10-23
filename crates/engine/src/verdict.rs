//! What a run says: how its process ended, what its reports counted, and the
//! verdict the two earn together. The exit code alone is never a pass.

use serde::{Deserialize, Serialize};

/// How a run ended, or that it has not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Running,
    Ok,
    Failed,
    Cancelled,
    /// Its process vanished, so how it ended is unknown.
    Lost,
}

/// What a run says about the thing it was checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Verdict {
    /// A report was read and everything in it passed.
    Passed,
    /// A report was read and something in it failed.
    Failed,
    /// The check never happened: the process never ran, or it was stopped.
    NotRun,
    /// It ran and left nothing that answers the question.
    Inconclusive,
}

/// What a run left that can be read as a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub passed: u32,
    pub failed: u32,
}

/// The verdict a run earns, from how its process ended and what it reported.
pub fn verdict(state: RunState, report: Option<Report>) -> Verdict {
    match state {
        RunState::Running | RunState::Cancelled => Verdict::NotRun,
        RunState::Lost => Verdict::Inconclusive,
        RunState::Failed => match report {
            Some(read) if read.failed > 0 => Verdict::Failed,
            _ => Verdict::Inconclusive,
        },
        RunState::Ok => match report {
            Some(read) if read.failed > 0 => Verdict::Failed,
            // Passing zero checks is not passing.
            Some(read) if read.passed == 0 => Verdict::Inconclusive,
            Some(_) => Verdict::Passed,
            None => Verdict::Inconclusive,
        },
    }
}

/// Failures kept by name; `failed` stays exact past it.
pub const MOST_FAILURES_KEPT: usize = 50;

/// One test that failed, as the report named it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FailedTest {
    pub name: String,
    /// Relative to where the run worked when it was under it.
    pub file: Option<String>,
    /// The first line of what it said, cut short.
    pub message: Option<String>,
}

/// What every report a run left said, added up.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tested {
    pub passed: u32,
    /// Tests that failed, and files that failed before any test in them ran.
    pub failed: u32,
    pub skipped: u32,
    /// At most [`MOST_FAILURES_KEPT`]; `failed` says how many there were.
    pub failures: Vec<FailedTest>,
    /// Formats read: `vitest`, `cargo test`, `JUnit`.
    pub read_from: Vec<String>,
}

impl Tested {
    /// Adds another report's counts and failures to these.
    pub fn add(&mut self, other: Tested) {
        self.passed += other.passed;
        self.failed += other.failed;
        self.skipped += other.skipped;
        let room = MOST_FAILURES_KEPT.saturating_sub(self.failures.len());
        self.failures.extend(other.failures.into_iter().take(room));
        for format in other.read_from {
            if !self.read_from.contains(&format) {
                self.read_from.push(format);
            }
        }
    }
}

#[cfg(test)]
#[path = "verdict_tests.rs"]
mod tests;
