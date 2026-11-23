//! The attack's numbers. Each run's are kept on its report and in the
//! project's ledger, beside its runs and never in the repository; the
//! project's are the ledger added up, with what the review's security reader
//! missed and the run mode they suggest. The month's budget is read from the
//! same ledger, so a run past it is refused before it starts.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::config::AttackRun;

/// The ledger, one line a run, in the runs' home.
pub const LEDGER: &str = "attack-ledger.jsonl";
/// The most of the ledger read.
const MOST_LEDGER: u64 = 4 * 1024 * 1024;
/// Runs before a mode is suggested.
const SEEN_ENOUGH: usize = 10;

fn number(value: &Value) -> f64 {
    value.as_f64().unwrap_or_default()
}

/// One run's numbers: hypotheses by result, cost and time over its
/// attackers, cost per confirmed hypothesis, and how many it confirmed
/// that the review's findings did not start (what the review missed).
pub fn of_report(report: &Value) -> Value {
    let hypotheses = report["hypotheses"].as_array().cloned().unwrap_or_default();
    let count = |status: &str| {
        hypotheses
            .iter()
            .filter(|one| one["status"] == status)
            .count()
    };
    let confirmed = count("confirmed");
    let attackers = report["attackers"].as_array().cloned().unwrap_or_default();
    let cost: f64 = attackers.iter().map(|one| number(&one["cost_usd"])).sum();
    let time: u64 = attackers
        .iter()
        .filter_map(|one| one["duration_ms"].as_u64())
        .sum();
    let missed = hypotheses
        .iter()
        .filter(|one| one["status"] == "confirmed" && one["from"] == "attack")
        .count();
    json!({
        "tried": count("tried"), "confirmed": confirmed, "refuted": count("refuted"),
        "not_run": count("not_run"), "cost_usd": cost, "duration_ms": time,
        // Exploits stopped by their environment or build: several say the
        // attack's test command lacks what the project needs.
        "env_error": report["counts"]["env_error"].as_u64().unwrap_or_default(),
        "env_repeated": crate::attack::env_repeated(report),
        "env_held": report["counts"]["env_held"].as_u64().unwrap_or_default(),
        "wall_ms": report["profile"]["total_ms"].as_u64(),
        "cost_per_confirmed": (confirmed > 0).then(|| cost / confirmed as f64),
        "missed_by_review": missed,
        "by_attacker": attackers.iter().map(|one| json!({
            "agent": one["agent"], "model": one["model"],
            "cost_usd": one["cost_usd"], "duration_ms": one["duration_ms"],
        })).collect::<Vec<_>>(),
    })
}

/// A run's numbers appended to the ledger: a later line for the same run
/// (once the session ran its exploits) stands for it.
pub fn record(home: &Path, item: &str, run: &str, report: &Value) -> Result<(), String> {
    std::fs::create_dir_all(home).map_err(|err| format!("{}: {err}", home.display()))?;
    let at = at_home(home).ok_or_else(|| format!("{LEDGER} leads out of {}", home.display()))?;
    let line = json!({
        "item": item, "run": run, "run_on": report["run_on"], "metrics": of_report(report),
    });
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&at)
        .map_err(|err| format!("{}: {err}", at.display()))?;
    writeln!(file, "{line}").map_err(|err| format!("{}: {err}", at.display()))
}

/// The ledger's place in the runs' home, never through a link out of it.
fn at_home(home: &Path) -> Option<PathBuf> {
    crate::fsguard::resolve_new(home, LEDGER).ok()
}

/// The ledger's runs, the last line of each; none when nothing ran yet.
/// Past its ceiling the newest part is read: what a month spent is never
/// left uncounted for its size. One that is there and cannot be read is an
/// error, never "nothing spent".
pub fn read_ledger(home: &Path) -> Result<Vec<Value>, String> {
    // A project's first attack: nothing ran, so nothing was spent.
    match std::fs::symlink_metadata(home) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(format!("{}: {err}", home.display())),
        Ok(_) => {}
    }
    let at = at_home(home).ok_or_else(|| format!("{LEDGER} leads out of {}", home.display()))?;
    let mut file = match std::fs::File::open(&at) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(format!("{}: {err}", at.display())),
    };
    let size = file
        .metadata()
        .map_err(|err| format!("{}: {err}", at.display()))?
        .len();
    let from = size.saturating_sub(MOST_LEDGER);
    file.seek(SeekFrom::Start(from))
        .map_err(|err| format!("{}: {err}", at.display()))?;
    let mut raw = Vec::new();
    file.take(MOST_LEDGER)
        .read_to_end(&mut raw)
        .map_err(|err| format!("{}: {err}", at.display()))?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    // Cut into a line: what is left of it is not a run.
    let text = match (from > 0, text.find('\n')) {
        (true, Some(end)) => text[end + 1..].to_owned(),
        _ => text,
    };
    let mut runs: Vec<Value> = Vec::new();
    for line in text.lines() {
        let Ok(one) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        runs.retain(|had| !(had["item"] == one["item"] && had["run"] == one["run"]));
        runs.push(one);
    }
    Ok(runs)
}

/// [`read_ledger`] for what is only shown: unreadable reads as none.
pub fn ledger(home: &Path) -> Vec<Value> {
    read_ledger(home).unwrap_or_default()
}

/// The calendar month of a run's stamp, `YYYYMM`.
pub fn month_of(stamp: &str) -> &str {
    stamp.get(..6).unwrap_or_default()
}

/// What the month's runs spent, in dollars.
pub fn spent_in(runs: &[Value], month: &str) -> f64 {
    runs.iter()
        .filter(|one| month_of(one["run"].as_str().unwrap_or_default()) == month)
        .map(|one| number(&one["metrics"]["cost_usd"]))
        .sum()
}

/// The project's numbers: every run added up, and the mode they suggest.
pub fn project(runs: &[Value], run_on: AttackRun) -> Value {
    let sum = |key: &str| -> u64 {
        runs.iter()
            .filter_map(|one| one["metrics"][key].as_u64())
            .sum()
    };
    let cost: f64 = runs
        .iter()
        .map(|one| number(&one["metrics"]["cost_usd"]))
        .sum();
    let confirmed = sum("confirmed");
    let mut said = json!({
        "runs": runs.len(), "cost_usd": cost, "duration_ms": sum("duration_ms"),
        "tried": sum("tried"), "confirmed": confirmed, "refuted": sum("refuted"),
        "not_run": sum("not_run"), "missed_by_review": sum("missed_by_review"),
        "cost_per_confirmed": (confirmed > 0).then(|| cost / confirmed as f64),
    });
    if let Some(suggested) = suggestion(runs.len(), confirmed, sum("missed_by_review"), run_on) {
        said["suggestion"] = json!(suggested);
    }
    said
}

/// The run mode the numbers point to, when they are enough to say.
pub fn suggestion(runs: usize, confirmed: u64, missed: u64, run_on: AttackRun) -> Option<String> {
    if runs < SEEN_ENOUGH {
        return None;
    }
    match run_on {
        AttackRun::PerItem if confirmed == 0 => Some(format!(
            "0 confirmed in {runs} per-item runs: consider sensitive"
        )),
        AttackRun::Release | AttackRun::Sensitive if missed > 0 => Some(format!(
            "{missed} confirmed holes the review missed in {runs} runs: consider per-item"
        )),
        _ => None,
    }
}

#[cfg(test)]
#[path = "attack_metrics_tests.rs"]
mod tests;
