//! The OpenRouter key, from `OPENROUTER_API_KEY` or the person's
//! `$XDG_CONFIG_HOME/devflow/credentials`, which only they can read. Never
//! written to a repository, never printed, never logged.

use std::path::{Path, PathBuf};

/// The variable read first.
pub const ENV: &str = "OPENROUTER_API_KEY";
/// The credentials file, under the person's devflow config folder.
pub const FILE: &str = "credentials";
/// The key's name in that file.
pub const KEY: &str = "openrouter_api_key";

pub fn file() -> Option<PathBuf> {
    devflow_engine::home::config_dir().map(|config| config.join(FILE))
}

/// The key, from the environment, else the credentials file.
pub fn openrouter_key() -> Option<String> {
    std::env::var(ENV)
        .ok()
        .map(|key| key.trim().to_owned())
        .filter(|key| !key.is_empty())
        .or_else(|| file().and_then(|file| read_key(&file)))
}

/// The key in a credentials file: `openrouter_api_key = <key>` on a line of
/// its own. A file others can read is not used.
pub fn read_key(file: &Path) -> Option<String> {
    if !private(file) {
        return None;
    }
    let text = std::fs::read_to_string(file).ok()?;
    text.lines().find_map(|line| {
        let (name, value) = line.split_once('=')?;
        (name.trim() == KEY)
            .then(|| value.trim().trim_matches('"').to_owned())
            .filter(|value| !value.is_empty())
    })
}

#[cfg(unix)]
fn private(file: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(file)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o077 == 0)
}

#[cfg(not(unix))]
fn private(file: &Path) -> bool {
    file.is_file()
}

#[cfg(test)]
#[path = "credentials_tests.rs"]
mod tests;
