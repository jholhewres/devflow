//! Where a card's work began in a checkout: `HEAD` when the card was started,
//! kept beside its runs.
//!
//! A card worked in the project's own folder has no base of its own, and a
//! review without one diffed from where `HEAD` left the default branch — a
//! hundred commits that were never the card's. The first start is the one
//! kept: starting again does not move where the work began.

use serde_json::{json, Value};

use crate::runs::Runs;

/// The file, beside the card's runs.
pub const STARTED: &str = "start.json";

/// Keeps `head` as where `card` began, unless a start is kept.
pub fn keep_start(runs: &Runs, card: &str, head: &str) -> Result<(), String> {
    let path = runs.file_in(card, None, STARTED)?;
    if path.exists() {
        return Ok(());
    }
    let text =
        serde_json::to_string_pretty(&json!({ "head": head })).map_err(|err| err.to_string())?;
    std::fs::write(&path, text).map_err(|err| format!("{}: {err}", path.display()))
}

/// The commit `card` began at, when one was kept.
pub fn start_of(runs: &Runs, card: &str) -> Option<String> {
    let path = runs.found(card, None, STARTED)?;
    let kept: Value = serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    kept["head"]
        .as_str()
        .filter(|head| !head.is_empty() && head.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_owned)
}

#[cfg(test)]
#[path = "started_tests.rs"]
mod tests;
