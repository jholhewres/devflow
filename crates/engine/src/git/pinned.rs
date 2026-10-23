//! A repository pinned at a ref: fetched into a bare cache devpit keeps, and
//! read blob by blob at the commit the ref named. Never checked out, never
//! built, and no hook or submodule of it runs — it is a team's Devflow layer,
//! which is somebody else's code until the person approved it.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::GitError;

/// The most a cache may hold once fetched: a layer is text, not a monorepo.
pub const MOST_CACHE_BYTES: u64 = 64 * 1024 * 1024;
/// The most of one file read out of it.
pub const MOST_FILE_BYTES: u64 = 256 * 1024;
/// The most files a pinned tree may list.
pub const MOST_FILES: usize = 2000;

/// One file of a pinned tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pinned {
    pub path: String,
    pub size: u64,
}

/// The cache for `url` under `root`, named by the address so two layers
/// never share one.
pub fn cache_for(root: &Path, url: &str) -> PathBuf {
    let digest = Sha256::digest(url.as_bytes());
    let name: String = digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    root.join(format!("{name}.git"))
}

/// A word git could read as an option, or a ref with what git refuses.
fn plain(word: &str, what: &str) -> Result<(), GitError> {
    let bad = word.is_empty()
        || word.starts_with('-')
        || word.contains("..")
        || word.chars().any(|one| one.is_control() || one == ' ');
    if bad {
        return Err(GitError::Refused(format!(
            "`{word}` is not a {what} devflow fetches"
        )));
    }
    Ok(())
}

/// git against the cache, never asking for a password and never running a
/// hook: with nobody at a terminal a prompt hangs, and a hook is code.
fn git(cache: &Path, args: &[&str]) -> Result<Vec<u8>, GitError> {
    let output = crate::env::command("git")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "")
        .env("GIT_SSH_COMMAND", "ssh -o BatchMode=yes")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.ext.allow=never",
        ])
        .arg("-C")
        .arg(cache)
        .args(args)
        .output()
        .map_err(|err| match err.kind() {
            std::io::ErrorKind::NotFound => GitError::Missing,
            _ => GitError::Failed {
                command: args.join(" "),
                stderr: err.to_string(),
            },
        })?;
    if !output.status.success() {
        return Err(GitError::Failed {
            command: args.join(" "),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(output.stdout)
}

fn text(bytes: Vec<u8>) -> String {
    String::from_utf8_lossy(&bytes).trim().to_owned()
}

/// What the cache holds on disk, counted up to just past `most`.
fn weight(folder: &Path, most: u64) -> u64 {
    let mut total = 0;
    let mut folders = vec![folder.to_path_buf()];
    while let Some(at) = folders.pop() {
        let Ok(entries) = std::fs::read_dir(&at) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let Ok(meta) = entry.path().symlink_metadata() else {
                continue;
            };
            if meta.is_dir() {
                folders.push(entry.path());
            } else {
                total += meta.len();
            }
            if total > most {
                return total;
            }
        }
    }
    total
}

/// Fetches `reference` of `url` into `cache` and answers the commit it names.
/// A cache past [`MOST_CACHE_BYTES`] is removed and refused.
pub fn fetch(cache: &Path, url: &str, reference: &str) -> Result<String, GitError> {
    plain(url, "repository address")?;
    plain(reference, "ref")?;
    if !cache.join("HEAD").is_file() {
        std::fs::create_dir_all(cache).map_err(|err| GitError::Refused(err.to_string()))?;
        git(cache, &["init", "--bare", "-q"])?;
    }
    git(
        cache,
        &[
            "fetch",
            "-q",
            "--no-tags",
            "--no-recurse-submodules",
            "--depth=1",
            "--",
            url,
            reference,
        ],
    )?;
    let commit = text(git(
        cache,
        &["rev-parse", "--verify", "FETCH_HEAD^{commit}"],
    )?);
    // Kept reachable, so the commit a lockfile names outlives the next fetch.
    git(
        cache,
        &["update-ref", &format!("refs/pinned/{commit}"), &commit],
    )?;
    if weight(cache, MOST_CACHE_BYTES) > MOST_CACHE_BYTES {
        let _ = std::fs::remove_dir_all(cache);
        return Err(GitError::Refused(format!(
            "{url} at {reference} is larger than {} MB, which no Devflow layer needs",
            MOST_CACHE_BYTES / 1024 / 1024
        )));
    }
    Ok(commit)
}

/// Whether the cache already holds `commit`.
pub fn holds(cache: &Path, commit: &str) -> bool {
    plain(commit, "commit").is_ok()
        && cache.join("HEAD").is_file()
        && git(cache, &["cat-file", "-e", &format!("{commit}^{{commit}}")]).is_ok()
}

/// The files of `commit`, with their sizes. Links and submodules are left
/// out: neither is a file a layer is read from.
pub fn files(cache: &Path, commit: &str) -> Result<Vec<Pinned>, GitError> {
    plain(commit, "commit")?;
    let listed = git(cache, &["ls-tree", "-r", "-l", "-z", commit])?;
    let mut found = Vec::new();
    for entry in listed
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let entry = String::from_utf8_lossy(entry);
        let Some((head, path)) = entry.split_once('\t') else {
            continue;
        };
        let words: Vec<&str> = head.split_whitespace().collect();
        let [mode, kind, _, size] = words[..] else {
            continue;
        };
        if kind != "blob" || mode == "120000" {
            continue;
        }
        found.push(Pinned {
            path: path.to_owned(),
            size: size.parse().unwrap_or(u64::MAX),
        });
        if found.len() > MOST_FILES {
            return Err(GitError::Refused(format!(
                "the layer holds more than {MOST_FILES} files"
            )));
        }
    }
    Ok(found)
}

/// One file of `commit`, refused past `most` bytes before it is read.
pub fn read(cache: &Path, commit: &str, path: &str, most: u64) -> Result<Vec<u8>, GitError> {
    plain(commit, "commit")?;
    if path.starts_with('-') || path.split('/').any(|part| part == "..") {
        return Err(GitError::Refused(format!(
            "`{path}` is not a path in the layer"
        )));
    }
    let named = format!("{commit}:{path}");
    let size: u64 = text(git(cache, &["cat-file", "-s", &named])?)
        .parse()
        .unwrap_or(u64::MAX);
    if size > most {
        return Err(GitError::Refused(format!(
            "{path} is larger than {} KB",
            most / 1024
        )));
    }
    git(cache, &["cat-file", "blob", &named])
}

/// SHA-256 of `bytes`, as a lockfile writes it.
pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "pinned_tests.rs"]
mod tests;
