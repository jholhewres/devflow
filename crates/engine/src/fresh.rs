//! Whether a run of a card's checks still holds: the commit and the tracked
//! files it read, kept in its `evidence.json`, against the checkout's now.
//! A run that recorded neither (before v0.2.2) is judged by when each changed
//! file was written, as it was.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::git;
use crate::runs;

/// The changed files looked at for when each was written.
const MOST_LOOKED: usize = 5_000;

/// The checkout a run read: its commit, and a print of what its tracked
/// files hold that the commit does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    pub head: String,
    pub tracked: String,
}

impl Tree {
    /// The tree `evidence.json` recorded, when it recorded one.
    pub fn of(evidence: &Value) -> Option<Tree> {
        let word = |key: &str| {
            evidence
                .get(key)
                .and_then(Value::as_str)
                .filter(|word| !word.is_empty())
                .map(str::to_owned)
        };
        Some(Tree {
            head: word("head")?,
            tracked: word("tree")?,
        })
    }
}

/// The checkout's tree now; `None` outside git or before its first commit.
pub fn tree_of(root: &Path) -> Option<Tree> {
    let head = git::head_of(root).ok()?;
    let diff = git::tracked_diff(root).ok()?;
    Some(Tree {
        head,
        tracked: format!("sha256:{:x}", Sha256::digest(diff.as_bytes())),
    })
}

/// The checkout paths the run's criteria name as proofs.
fn proofs(evidence: &Value) -> Vec<String> {
    evidence
        .get("criteria")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|seen| seen.get("proof")?.get("path")?.as_str())
        .map(|path| path.trim_start_matches("./").to_owned())
        .collect()
}

/// When the checkout's code last changed, as a run's stamp, for the gate's
/// `changed`; `None` when git cannot tell. `ours` are the folders that are
/// never code. With the run's recorded tree, a commit or a tracked edit since
/// makes the run old whatever the clocks say, and of the untracked files
/// only those that are not a criterion's proof count, by when each was
/// written.
pub fn changed_at(root: &Path, run: Option<(&str, &Value)>, ours: &[&str]) -> Option<String> {
    let newest = |paths: Vec<&String>| {
        paths
            .into_iter()
            .filter(|path| !ours.iter().any(|folder| path.starts_with(folder)))
            .take(MOST_LOOKED)
            .filter_map(|path| {
                std::fs::symlink_metadata(root.join(path))
                    .ok()?
                    .modified()
                    .ok()
            })
            .max()
    };
    let since = run.and_then(|(name, _)| runs::seconds_of(name));
    let everything = || -> Option<Option<SystemTime>> {
        let dirty = git::dirty(root).ok()?;
        let committed = since.map_or_else(Vec::new, |since| git::touched_since(root, since));
        Some(newest(dirty.iter().chain(&committed).collect()))
    };
    let recorded = run.and_then(|(_, evidence)| Some((Tree::of(evidence)?, evidence)));
    let Some((recorded, evidence)) = recorded else {
        return everything()?.map(runs::stamp);
    };
    let now = tree_of(root)?;
    if now == recorded {
        let proofs = proofs(evidence);
        let untracked = git::untracked(root).ok()?;
        return newest(
            untracked
                .iter()
                .filter(|path| !proofs.contains(path))
                .collect(),
        )
        .map(runs::stamp);
    }
    // The code changed: a stamp after the run, even within its second.
    let just_after = since.map(|since| UNIX_EPOCH + Duration::from_secs(since + 1));
    let seen = everything().flatten();
    [seen, just_after]
        .into_iter()
        .flatten()
        .max()
        .map(runs::stamp)
}

#[cfg(test)]
#[path = "fresh_tests.rs"]
mod tests;
