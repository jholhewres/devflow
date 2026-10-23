//! Test reports: files in `$DEVFLOW_REPORT_DIR` (vitest/jest JSON, JUnit XML,
//! `go test -json`) and what `cargo test` or `go test -json` printed. Nothing
//! recognised means no result, never a pass.

use std::path::Path;

use crate::verdict::Tested;

mod cargo;
mod cases;
mod go;
mod junit;
mod vitest;

pub use cases::{outcome_of, Case, Outcome, Reported, MOST_CASES};

/// Largest report file read, checked before reading.
pub const MOST_REPORT: u64 = 32 * 1024 * 1024;

/// The most report files read from one run's folder.
pub const MOST_REPORTS: usize = 32;

/// The longest failure message kept, in characters.
const LONGEST_MESSAGE: usize = 300;

/// Everything the run reported, added up, or `None`. `printed` is `None` when
/// the output was cut: half an output may have lost the failures.
pub fn read(dir: Option<&Path>, printed: Option<&str>, cwd: &Path) -> Option<Tested> {
    read_cases(dir, printed, cwd).map(|reported| reported.tested)
}

/// [`read`], with each test the reports named and how it ended.
pub fn read_cases(dir: Option<&Path>, printed: Option<&str>, cwd: &Path) -> Option<Reported> {
    let mut found: Option<Reported> = None;
    let mut take = |reported: Reported| found.get_or_insert_with(Reported::default).add(reported);

    for text in dir.map(files_in).unwrap_or_default() {
        if let Some(reported) = file_cases(&text, cwd) {
            take(reported);
        }
    }
    if let Some(reported) =
        printed.and_then(|printed| cargo::from_output(printed).or_else(|| go::from_lines(printed)))
    {
        take(reported);
    }
    found
}

/// A report file's text, in whichever format it turns out to be.
pub fn from_file(text: &str, cwd: &Path) -> Option<Tested> {
    file_cases(text, cwd).map(|reported| reported.tested)
}

fn file_cases(text: &str, cwd: &Path) -> Option<Reported> {
    match text.trim_start().as_bytes().first()? {
        b'{' => vitest::from_json(text, cwd).or_else(|| go::from_lines(text)),
        b'<' => junit::from_xml(text, cwd),
        _ => None,
    }
}

/// Regular files in `dir`, by name, under [`MOST_REPORT`]. Links are skipped.
fn files_in(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<_> = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .symlink_metadata()
                .is_ok_and(|meta| meta.is_file() && meta.len() <= MOST_REPORT)
        })
        .map(|entry| entry.path())
        .collect();
    paths.sort();
    paths
        .into_iter()
        .take(MOST_REPORTS)
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .collect()
}

/// The first line worth reading of a failure, without colour codes, cut short.
pub(crate) fn short(message: &str) -> Option<String> {
    let plain = without_colour(message);
    let line = plain.lines().map(str::trim).find(|line| !line.is_empty())?;
    Some(if line.chars().count() > LONGEST_MESSAGE {
        let cut: String = line.chars().take(LONGEST_MESSAGE).collect();
        format!("{cut}…")
    } else {
        line.to_owned()
    })
}

/// `path` relative to `cwd` when it is under it, as written otherwise.
pub(crate) fn relative(path: &str, cwd: &Path) -> String {
    let path = path.strip_prefix("file://").unwrap_or(path);
    Path::new(path)
        .strip_prefix(cwd)
        .map(|rest| rest.display().to_string())
        .unwrap_or_else(|_| path.to_owned())
}

/// Text with its ANSI escape sequences taken out.
fn without_colour(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            if chars.next() == Some('[') {
                for next in chars.by_ref() {
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
