//! A team layer's ref, from the commit it names to the person's approval.
//! Fetching shows what approving would change and applies nothing; only the
//! approval writes the lockfile, with every file's hash, and only for the
//! commit the person was shown.

use std::collections::BTreeMap;
use std::path::Path;

use crate::git::pinned;
use serde::Serialize;

use crate::config::Extend;
use crate::layers::{name_of, read_lock, write_lock, Home, Locked, LAYER_FILE};

/// What approving a layer's ref changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    pub name: String,
    pub git: String,
    /// What the lockfile pins now, when it pins this layer.
    pub from_ref: Option<String>,
    pub from_commit: Option<String>,
    pub to_ref: String,
    pub to_commit: String,
    /// Each file that differs: `added`, `removed` or `changed`.
    pub files: Vec<(String, &'static str)>,
    /// The layer's devflow.yaml, line by line: `- ` gone, `+ ` new.
    pub diff: Vec<String>,
}

/// Every file of `commit` and its hash, each read under the ceiling.
fn hashed(cache: &Path, commit: &str) -> Result<BTreeMap<String, String>, String> {
    let mut files = BTreeMap::new();
    for file in pinned::files(cache, commit).map_err(|err| err.to_string())? {
        if file.size > pinned::MOST_FILE_BYTES {
            return Err(format!(
                "{} is larger than {} KB, which no Devflow layer needs",
                file.path,
                pinned::MOST_FILE_BYTES / 1024
            ));
        }
        let bytes = pinned::read(cache, commit, &file.path, pinned::MOST_FILE_BYTES)
            .map_err(|err| err.to_string())?;
        files.insert(file.path, pinned::digest(&bytes));
    }
    Ok(files)
}

fn text_at(cache: &Path, commit: &str, path: &str) -> Vec<String> {
    pinned::read(cache, commit, path, pinned::MOST_FILE_BYTES)
        .ok()
        .map(|bytes| {
            String::from_utf8_lossy(&bytes)
                .lines()
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// The lines only one side has, the way a person scans a change.
fn lines_changed(before: &[String], after: &[String]) -> Vec<String> {
    let gone = before
        .iter()
        .filter(|line| !after.contains(line))
        .map(|line| format!("- {line}"));
    let new = after
        .iter()
        .filter(|line| !before.contains(line))
        .map(|line| format!("+ {line}"));
    gone.chain(new).collect()
}

/// Fetches the ref devflow.yaml names for `layer` and says what approving
/// it would change. Nothing is applied, and nothing fetched is run.
pub fn fetched(root: &Path, layer: &Extend, home: &Home) -> Result<Change, String> {
    let cache = pinned::cache_for(&home.teams, &layer.git);
    let commit =
        pinned::fetch(&cache, &layer.git, &layer.reference).map_err(|err| err.to_string())?;
    let now = hashed(&cache, &commit)?;
    let lock = read_lock(root)?;
    let locked = lock.extends.iter().find(|one| one.git == layer.git);
    let before = locked.map(|one| one.files.clone()).unwrap_or_default();
    let mut files: Vec<(String, &'static str)> = now
        .iter()
        .filter_map(|(path, digest)| match before.get(path) {
            None => Some((path.clone(), "added")),
            Some(was) if was != digest => Some((path.clone(), "changed")),
            Some(_) => None,
        })
        .collect();
    files.extend(
        before
            .keys()
            .filter(|path| !now.contains_key(*path))
            .map(|path| (path.clone(), "removed")),
    );
    files.sort();
    let was = locked
        .filter(|one| pinned::holds(&cache, &one.commit))
        .map(|one| text_at(&cache, &one.commit, LAYER_FILE))
        .unwrap_or_default();
    Ok(Change {
        name: name_of(&layer.git),
        git: layer.git.clone(),
        from_ref: locked.map(|one| one.reference.clone()),
        from_commit: locked.map(|one| one.commit.clone()),
        to_ref: layer.reference.clone(),
        diff: lines_changed(&was, &text_at(&cache, &commit, LAYER_FILE)),
        to_commit: commit,
        files,
    })
}

/// The person's approval: `layer` pinned at `commit` — the commit they were
/// shown — with the hash of every file, in the project's lockfile.
pub fn approve(root: &Path, layer: &Extend, commit: &str, home: &Home) -> Result<Locked, String> {
    let cache = pinned::cache_for(&home.teams, &layer.git);
    if !pinned::holds(&cache, commit) {
        return Err(format!(
            "{commit} of {} is not on this machine: look at the change again",
            layer.git
        ));
    }
    let locked = Locked {
        git: layer.git.clone(),
        reference: layer.reference.clone(),
        commit: commit.to_owned(),
        files: hashed(&cache, commit)?,
    };
    let mut lock = read_lock(root)?;
    lock.extends.retain(|one| one.git != layer.git);
    lock.extends.push(locked.clone());
    write_lock(root, &lock)?;
    Ok(locked)
}

#[cfg(test)]
#[path = "pinning_tests.rs"]
mod tests;
