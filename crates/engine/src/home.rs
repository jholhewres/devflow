//! What devflow keeps outside a project: the person's own layer under
//! `$XDG_CONFIG_HOME/devflow/` and the team layers' cache under
//! `$XDG_CACHE_HOME/devflow/`, with `~/.config` and `~/.cache` when unset.

use std::path::{Path, PathBuf};

/// `$XDG_CONFIG_HOME/devflow`, the person's layer, skills and credentials.
pub fn config_dir() -> Option<PathBuf> {
    xdg("XDG_CONFIG_HOME", ".config")
}

/// `$XDG_CACHE_HOME/devflow`, what devflow can fetch again.
pub fn cache_dir() -> Option<PathBuf> {
    xdg("XDG_CACHE_HOME", ".cache")
}

fn xdg(variable: &str, fallback: &str) -> Option<PathBuf> {
    let base = std::env::var_os(variable)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| user_home().map(|home| home.join(fallback)))?;
    Some(base.join("devflow"))
}

fn user_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

/// The person's own layer: a `devflow.yaml` read under every project's.
pub fn personal(config: &Path) -> PathBuf {
    config.to_path_buf()
}

/// The person's skills, `<config>/skills/<name>/SKILL.md`.
pub fn skills(config: &Path) -> PathBuf {
    config.join("skills")
}

/// The person's reviewer personas, `<config>/reviewers/<name>.md`.
pub fn reviewers(config: &Path) -> PathBuf {
    config.join("reviewers")
}

/// The team layers a project extends, one bare repository each.
pub fn teams(cache: &Path) -> PathBuf {
    cache.join("teams")
}

#[cfg(test)]
#[path = "home_tests.rs"]
mod tests;
