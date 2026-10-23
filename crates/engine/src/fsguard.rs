//! Paths inside a project, safely: every path handed back has been resolved
//! through symlinks and then checked for containment in the root, in that
//! order, so a link pointing out of the project is refused.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum TreeError {
    Outside {
        path: PathBuf,
    },
    Unreadable {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl std::fmt::Display for TreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TreeError::Outside { path } => write!(f, "{} is outside the project", path.display()),
            TreeError::Unreadable { path, source } => {
                write!(f, "could not read {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for TreeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TreeError::Unreadable { source, .. } => Some(source),
            TreeError::Outside { .. } => None,
        }
    }
}

/// Resolves `relative` against `root` and refuses anything that escapes.
///
/// Returns the canonical path, so callers cannot accidentally keep using the
/// unresolved one.
pub fn resolve(root: &Path, relative: &str) -> Result<PathBuf, TreeError> {
    let root = root
        .canonicalize()
        .map_err(|source| TreeError::Unreadable {
            path: root.to_path_buf(),
            source,
        })?;

    let candidate = if relative.is_empty() {
        root.clone()
    } else {
        root.join(relative)
    };

    // Canonicalize first, compare second. A `..` segment or a symlink is only
    // visible after resolution, and comparing the strings before it is exactly
    // the check that looks right and is not.
    let resolved = candidate
        .canonicalize()
        .map_err(|source| TreeError::Unreadable {
            path: candidate.clone(),
            source,
        })?;

    if !resolved.starts_with(&root) {
        return Err(TreeError::Outside { path: resolved });
    }

    Ok(resolved)
}

/// An absolute path as a project-relative one, or an error when it is not in
/// the project.
///
/// Resolved through symlinks before the comparison, for the same reason as
/// `resolve`: comparing the strings first is the check that looks right and
/// is not.
pub fn relative_to(root: &Path, absolute: &Path) -> Result<String, TreeError> {
    let root = root
        .canonicalize()
        .map_err(|source| TreeError::Unreadable {
            path: root.to_path_buf(),
            source,
        })?;
    let resolved = absolute
        .canonicalize()
        .map_err(|source| TreeError::Unreadable {
            path: absolute.to_path_buf(),
            source,
        })?;
    resolved
        .strip_prefix(&root)
        .map(|rest| rest.to_string_lossy().into_owned())
        .map_err(|_| TreeError::Outside { path: resolved })
}

/// Whether any segment of `relative` is `.git`, in any case (`.GIT` is the
/// same folder on macOS). `pub(crate)` so `paths_tests.rs` can call it.
pub(crate) fn touches_git(relative: &str) -> bool {
    relative
        .split('/')
        .any(|segment| segment.eq_ignore_ascii_case(".git"))
}

/// Whether `resolved`, already canonical, sits inside `.git` below `root` —
/// the string check misses a symlinked folder that leads there.
fn under_git(root: &Path, resolved: &Path) -> bool {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    resolved.strip_prefix(&root).is_ok_and(|rest| {
        rest.components()
            .any(|part| part.as_os_str().eq_ignore_ascii_case(".git"))
    })
}

fn clear_of_git(root: &Path, resolved: PathBuf) -> Result<PathBuf, TreeError> {
    if under_git(root, &resolved) {
        return Err(TreeError::Outside { path: resolved });
    }
    Ok(resolved)
}

/// The parent resolved through symlinks, with the final name joined as
/// written. The root however it is spelled — `""`, `.`, `sub/..` — ends in an
/// empty, `.` or `..` name, and is refused here.
fn beside_parent(root: &Path, relative: &str) -> Result<PathBuf, TreeError> {
    let relative = relative.trim_end_matches('/');
    let (parent, name) = relative.rsplit_once('/').unwrap_or(("", relative));
    if name.is_empty() || name == "." || name == ".." || touches_git(relative) {
        return Err(TreeError::Outside {
            path: root.join(relative),
        });
    }
    Ok(resolve(root, parent)?.join(name))
}

/// Resolves `relative` against `root` without requiring it to exist.
pub fn resolve_new(root: &Path, relative: &str) -> Result<PathBuf, TreeError> {
    let candidate = beside_parent(root, relative)?;

    // `symlink_metadata`, not `exists`: `exists` follows the link and asks
    // about its *target*, so a broken symlink — pointing at nothing — reads
    // as absent and would fall through unexamined. A name is "already there"
    // the moment something sits at it, valid or not, and only `resolve`'s own
    // canonicalise-then-check on the whole path can vouch for what it is. A
    // broken link fails that canonicalisation and is refused, correctly: the
    // name is taken by something this cannot vouch for.
    if candidate.symlink_metadata().is_ok() {
        return clear_of_git(root, resolve(root, relative)?);
    }
    clear_of_git(root, candidate)
}

/// At most `ceiling` bytes, or `None` when there are more: one byte past the
/// ceiling is read, so a file too big is refused without being held.
pub fn read_within(reader: impl Read, ceiling: u64) -> std::io::Result<Option<Vec<u8>>> {
    let mut raw = Vec::new();
    reader
        .take(ceiling.saturating_add(1))
        .read_to_end(&mut raw)?;
    Ok((raw.len() as u64 <= ceiling).then_some(raw))
}

/// Where a write lands before it is renamed over the file: beside it, and
/// hidden, so a listing never shows it.
pub fn temp_for(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!(".{name}.tmp"))
}

/// Writes `bytes` beside `dir/name`, then renames over it, so a reader sees
/// the old file or the new one and never half of either.
///
/// `create_new` refuses a link or a directory planted at the temp name, and
/// `rename` replaces a link at the target instead of writing through it.
pub fn replace(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let temp = temp_for(dir, name);
    // A write that died leaves a file; `create_new` refuses whatever else is there.
    if temp.symlink_metadata().is_ok_and(|meta| meta.is_file()) {
        let _ = std::fs::remove_file(&temp);
    }
    let mut made_temp = false;
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .and_then(|mut file| {
            made_temp = true;
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&temp, dir.join(name)));
    if written.is_err() && made_temp {
        let _ = std::fs::remove_file(&temp);
    }
    written
}

#[cfg(test)]
#[path = "fsguard_tests.rs"]
mod tests;
