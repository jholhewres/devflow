//! Where a project keeps its configuration: `stagegate.yaml` at the root,
//! else `.stagegate/stagegate.yaml`, else devpit's
//! `.devpit/devflow/devflow.yaml`, read where it is so a project already on
//! devpit's Devflow needs no migration.

use std::path::{Path, PathBuf};

/// The file at the project's root.
pub const FILE: &str = "stagegate.yaml";
/// The folder that keeps the file, its scripts and its runs.
pub const DIR: &str = ".stagegate";
/// Where devpit's Devflow keeps the same configuration.
pub const DEVPIT: &str = ".devpit/devflow/devflow.yaml";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Root,
    Folder,
    Devpit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub path: PathBuf,
    pub origin: Origin,
}

/// The configuration that applies to `root`, in the order above. A file that
/// resolves outside the root, through a symlink, is not the project's.
pub fn config_in(root: &Path) -> Option<Found> {
    let root = root.canonicalize().ok()?;
    [
        (PathBuf::from(FILE), Origin::Root),
        (Path::new(DIR).join(FILE), Origin::Folder),
        (PathBuf::from(DEVPIT), Origin::Devpit),
    ]
    .into_iter()
    .find_map(|(relative, origin)| {
        let path = root.join(relative).canonicalize().ok()?;
        (path.starts_with(&root) && path.is_file()).then_some(Found { path, origin })
    })
}

#[cfg(test)]
#[path = "locate_tests.rs"]
mod tests;
