//! The decision log: every question asked of Decisions, what came of it and
//! the person's label on it later — one JSON line each in
//! `$XDG_STATE_HOME/devflow/decisions.jsonl`, never the state itself, only
//! its digest.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const FILE: &str = "decisions.jsonl";
/// The most of the log read; past it the oldest lines are not.
const MOST_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Row {
    pub id: String,
    pub at: i64,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub item: Option<String>,
    pub gate: String,
    pub mode: String,
    #[serde(default)]
    pub rubric: Option<String>,
    #[serde(default)]
    pub rubric_version: Option<String>,
    pub questions: String,
    #[serde(default)]
    pub answers: Option<String>,
    #[serde(default)]
    pub thresholds: Option<String>,
    pub outcome: String,
    pub cost_usd: f64,
    pub latency_ms: i64,
    pub state_digest: String,
    #[serde(default)]
    pub failure: Option<String>,
    /// The person's label: `pass` or `fail`.
    #[serde(default)]
    pub person_verdict: Option<String>,
    #[serde(default)]
    pub person_action: Option<String>,
}

/// A label, kept as a line of its own after the row it names.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Label {
    label: String,
    verdict: String,
    action: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Log {
    file: PathBuf,
}

impl Log {
    pub fn of_user() -> Log {
        let folder =
            devflow_engine::home::state_dir().unwrap_or_else(|| PathBuf::from(".devflow-home"));
        Log::at(&folder.join(FILE))
    }

    pub fn at(file: &Path) -> Log {
        Log {
            file: file.to_path_buf(),
        }
    }

    fn append(&self, line: &str) -> Result<(), String> {
        let folder = self.file.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(folder).map_err(|err| format!("{}: {err}", folder.display()))?;
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&self.file)
            .map_err(|err| format!("{}: {err}", self.file.display()))?;
        writeln!(file, "{line}").map_err(|err| format!("{}: {err}", self.file.display()))
    }

    /// Keeps a decision, and answers its id.
    pub fn write(&self, mut row: Row) -> Result<String, String> {
        if row.id.is_empty() {
            row.id = id_of(&row);
        }
        let line = serde_json::to_string(&row).map_err(|err| err.to_string())?;
        self.append(&line)?;
        Ok(row.id)
    }

    /// The person's verdict on a decision, and what they did.
    pub fn label(&self, id: &str, passing: bool, action: &str) -> Result<(), String> {
        let label = Label {
            label: id.to_owned(),
            verdict: if passing { "pass" } else { "fail" }.to_owned(),
            action: action.to_owned(),
        };
        self.append(&serde_json::to_string(&label).map_err(|err| err.to_string())?)
    }

    /// Every decision, newest first, with the person's labels on them.
    pub fn rows(&self) -> Vec<Row> {
        let Ok(file) = std::fs::File::open(&self.file) else {
            return Vec::new();
        };
        let raw = devflow_engine::fsguard::read_within(file, MOST_BYTES)
            .ok()
            .flatten()
            .unwrap_or_default();
        let text = String::from_utf8_lossy(&raw);
        let mut rows: Vec<Row> = Vec::new();
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            if let Ok(label) = serde_json::from_str::<Label>(line) {
                if let Some(row) = rows.iter_mut().find(|row| row.id == label.label) {
                    row.person_verdict = Some(label.verdict);
                    row.person_action = Some(label.action);
                }
                continue;
            }
            if let Ok(row) = serde_json::from_str::<Row>(line) {
                rows.push(row);
            }
        }
        rows.reverse();
        rows
    }

    /// What decisions cost since `since`, in dollars.
    pub fn spend_since(&self, since: i64) -> f64 {
        self.rows()
            .iter()
            .filter(|row| row.at >= since)
            .map(|row| row.cost_usd)
            .fold(0.0, |total, cost| total + cost)
    }

    /// Why the project's last call came to nothing, if it did.
    pub fn failed_last(&self, project: &str) -> Option<String> {
        self.rows()
            .into_iter()
            .find(|row| row.project.as_deref() == Some(project))?
            .failure
    }

    pub fn of_project(&self, project: &str) -> Vec<Row> {
        self.rows()
            .into_iter()
            .filter(|row| row.project.as_deref() == Some(project))
            .collect()
    }

    /// An item's decisions by one rubric, newest first.
    pub fn of_item(&self, item: &str, rubric: &str) -> Vec<Row> {
        self.rows()
            .into_iter()
            .filter(|row| {
                row.item.as_deref() == Some(item) && row.rubric.as_deref() == Some(rubric)
            })
            .collect()
    }
}

fn id_of(row: &Row) -> String {
    use sha2::{Digest, Sha256};
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    let seed = format!(
        "{nanos}:{}:{}:{}",
        std::process::id(),
        row.gate,
        row.state_digest
    );
    let hash = Sha256::digest(seed.as_bytes());
    let hex: String = hash
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("dec_{hex}")
}

#[cfg(test)]
#[path = "log_tests.rs"]
mod tests;
