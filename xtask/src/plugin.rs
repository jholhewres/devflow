//! `cargo xtask plugin-sync`: the Claude Code plugin's skills, commands,
//! agents and hooks at the repository's root, as the flow makes them.
//! `--check` writes nothing and fails on a file that drifted or is extra.

use std::path::Path;

/// The folders the plugin's files are in, which nothing else writes to.
pub const FOLDERS: [&str; 4] = ["skills", "commands", "agents", "hooks"];

/// What differs between the plugin's files and the root's, by path.
pub fn drift(root: &Path, files: &[(String, String)]) -> Vec<String> {
    let mut drifted: Vec<String> = files
        .iter()
        .filter(|(path, text)| std::fs::read_to_string(root.join(path)).ok().as_ref() != Some(text))
        .map(|(path, _)| format!("{path} is not as the flow makes it"))
        .collect();
    for path in present(root) {
        if !files.iter().any(|(made, _)| *made == path) {
            drifted.push(format!("{path} is not a file of the plugin"));
        }
    }
    drifted
}

/// What differs of files that live beside others of the root's.
pub fn drift_of(root: &Path, files: &[(String, String)]) -> Vec<String> {
    files
        .iter()
        .filter(|(path, text)| std::fs::read_to_string(root.join(path)).ok().as_ref() != Some(text))
        .map(|(path, _)| format!("{path} is not as the flow makes it"))
        .collect()
}

/// Writes files that live beside others of the root's.
pub fn write_each(root: &Path, files: &[(String, String)]) -> Result<(), String> {
    for (path, text) in files {
        let at = root.join(path);
        if std::fs::read_to_string(&at).ok().as_ref() == Some(text) {
            continue;
        }
        if let Some(parent) = at.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{path}: {e}"))?;
        }
        std::fs::write(&at, text).map_err(|e| format!("{path}: {e}"))?;
    }
    Ok(())
}

/// Every file now in the plugin's folders, relative to the root.
fn present(root: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut folders: Vec<String> = FOLDERS.iter().map(|one| (*one).to_owned()).collect();
    while let Some(folder) = folders.pop() {
        let Ok(entries) = std::fs::read_dir(root.join(&folder)) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = format!("{folder}/{}", entry.file_name().to_string_lossy());
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => folders.push(path),
                Ok(_) => found.push(path),
                Err(_) => {}
            }
        }
    }
    found.sort();
    found
}

/// Writes the plugin's files and removes what the flow no longer makes.
pub fn write(root: &Path, files: &[(String, String)]) -> Result<usize, String> {
    for path in present(root) {
        if !files.iter().any(|(made, _)| *made == path) {
            std::fs::remove_file(root.join(&path)).map_err(|e| format!("{path}: {e}"))?;
        }
    }
    let mut written = 0;
    for (path, text) in files {
        let at = root.join(path);
        if std::fs::read_to_string(&at).ok().as_ref() == Some(text) {
            continue;
        }
        if let Some(parent) = at.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{path}: {e}"))?;
        }
        std::fs::write(&at, text).map_err(|e| format!("{path}: {e}"))?;
        written += 1;
    }
    Ok(written)
}

#[cfg(test)]
#[path = "plugin_tests.rs"]
mod tests;
