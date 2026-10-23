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

/// Writes the key to the credentials file, readable by the person only.
pub fn write_key(file: &Path, key: &str) -> Result<(), String> {
    let folder = file.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(folder).map_err(|err| format!("{}: {err}", folder.display()))?;
    let kept: Vec<String> = std::fs::read_to_string(file)
        .unwrap_or_default()
        .lines()
        .filter(|line| {
            line.split_once('=')
                .is_none_or(|(name, _)| name.trim() != KEY)
        })
        .map(str::to_owned)
        .collect();
    let mut text = kept.join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    text.push_str(&format!("{KEY} = {}\n", key.trim()));
    let name = file
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| FILE.to_owned());
    let temp = folder.join(format!(".{name}.{}.tmp", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = options.open(&temp).and_then(|mut out| {
        use std::io::Write;
        out.write_all(text.as_bytes())?;
        out.sync_all()
    });
    let renamed = written.and_then(|()| std::fs::rename(&temp, file));
    if renamed.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    renamed.map_err(|err| format!("{}: {err}", file.display()))
}

/// Takes the key out of the credentials file, keeping the rest.
pub fn forget_key(file: &Path) -> Result<bool, String> {
    let Ok(text) = std::fs::read_to_string(file) else {
        return Ok(false);
    };
    let kept: Vec<&str> = text
        .lines()
        .filter(|line| {
            line.split_once('=')
                .is_none_or(|(name, _)| name.trim() != KEY)
        })
        .collect();
    if kept.len() == text.lines().count() {
        return Ok(false);
    }
    let rest = kept.join("\n");
    if rest.trim().is_empty() {
        std::fs::remove_file(file).map_err(|err| format!("{}: {err}", file.display()))?;
    } else {
        std::fs::write(file, format!("{rest}\n"))
            .map_err(|err| format!("{}: {err}", file.display()))?;
    }
    Ok(true)
}

/// Where the key in use comes from, never the key itself.
pub fn source() -> Option<&'static str> {
    if std::env::var(ENV).is_ok_and(|key| !key.trim().is_empty()) {
        return Some(ENV);
    }
    file()
        .and_then(|file| read_key(&file))
        .map(|_| "credentials")
}

#[cfg(test)]
#[path = "credentials_tests.rs"]
mod tests;
