//! Where an attack with no work item keeps its runs and exploits: a vault in
//! devflow's cache for the project, never inside the checkout, so an exploit
//! of code already merged is never left in the repository. `devflow attack
//! promote` copies one in, at its path, when the person wants it there.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::runs::Runs;

/// The vault's folder in the project's cache.
pub const VAULT: &str = "vault";

/// The vault under `cache`, made when missing; refused when it resolves
/// inside the checkout.
pub fn home(cache: &Path, checkout: &Path) -> Result<PathBuf, String> {
    outside(&cache.join(VAULT), checkout)
}

/// `folder`, made when missing, as it resolves; refused when that is inside
/// the checkout: an exploit is never kept in the repository.
pub fn outside(folder: &Path, checkout: &Path) -> Result<PathBuf, String> {
    let tree = checkout
        .canonicalize()
        .unwrap_or_else(|_| checkout.to_path_buf());
    let inside = |real: &Path| {
        Err(format!(
            "the vault {} is inside the checkout: an exploit is never kept in the repository; set XDG_CACHE_HOME outside it",
            real.display()
        ))
    };
    // Judged where it would resolve before anything is made: the nearest
    // folder that exists, as it resolves, with the rest of the path.
    let mut existing = folder;
    let mut rest = Vec::new();
    while std::fs::symlink_metadata(existing).is_err() {
        let (Some(parent), Some(name)) = (existing.parent(), existing.file_name()) else {
            break;
        };
        rest.push(name);
        existing = parent;
    }
    if let Ok(real) = existing.canonicalize() {
        let would = rest.iter().rev().fold(real, |at, name| at.join(name));
        if would.starts_with(&tree) {
            return inside(&would);
        }
    }
    std::fs::create_dir_all(folder).map_err(|err| format!("{}: {err}", folder.display()))?;
    let real = folder
        .canonicalize()
        .map_err(|err| format!("{}: {err}", folder.display()))?;
    if real.starts_with(&tree) {
        return inside(&real);
    }
    Ok(real)
}

/// The runs kept in the vault at `home`.
pub fn runs(home: PathBuf, checkout: &Path) -> Runs {
    Runs {
        dialect: &crate::Dialect::DEVFLOW,
        home,
        checkout: checkout.to_path_buf(),
    }
}

/// Copies hypothesis `id`'s exploit, kept in the run's `folder`, into the
/// repository at `root` at its own path. A path that leads out of the
/// repository, through `..` or a link, is refused, and so is one already
/// there.
pub fn promote(root: &Path, folder: &Path, report: &Value, id: &str) -> Result<String, String> {
    let one = report["hypotheses"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|one| one["id"] == id)
        .ok_or_else(|| format!("the report has no hypothesis `{id}`"))?;
    let path = one["exploit"]["path"]
        .as_str()
        .ok_or_else(|| format!("{id} has no exploit"))?;
    let path = crate::attack::exploit_path(path)?;
    // Never where a tool runs a file on its own: a hidden folder or file
    // (`.github/workflows`, `.husky`, `.vscode`).
    if Path::new(&path)
        .components()
        .any(|part| part.as_os_str().to_string_lossy().starts_with('.'))
    {
        return Err(format!(
            "{path} is hidden, where a tool may run it on its own: an exploit belongs with the tests"
        ));
    }
    let saved = one["exploit"]["saved"]
        .as_str()
        .ok_or_else(|| format!("{id}'s exploit was not kept"))?;
    let source = crate::fsguard::resolve(folder, saved)
        .map_err(|_| format!("{saved} leads out of its run"))?;
    let file =
        std::fs::File::open(&source).map_err(|err| format!("{}: {err}", source.display()))?;
    let raw = crate::fsguard::read_within(file, crate::attack::MOST_CODE as u64)
        .map_err(|err| format!("{}: {err}", source.display()))?
        .ok_or_else(|| format!("{saved} is larger than an exploit"))?;
    let code = String::from_utf8(raw).map_err(|_| format!("{saved} is not text"))?;
    if std::fs::symlink_metadata(root.join(&path)).is_ok() {
        return Err(format!("{path} is there already: nothing is overwritten"));
    }
    // Each folder on the way and the file itself, never through a link out.
    crate::attack::put(root, &path, &code)?;
    Ok(path)
}

#[cfg(test)]
#[path = "vault_tests.rs"]
mod tests;
