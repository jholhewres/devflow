//! What only the person decides, kept on their machine: devflow switched on
//! in a project, Decisions moved to `enforce` there, and a team layer's
//! command confirmed at its commit. A terminal command with a confirmation
//! writes it (`devflow config set`, `devflow stage confirm`); an MCP tool
//! only reads it, and answers with the command to run.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use devflow_engine::Ask;
use serde::{Deserialize, Serialize};

const FILE: &str = "consent.json";
/// The newest confirmed commands kept: an old one that comes back is asked again.
const MOST_COMMANDS: usize = 256;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Kept {
    #[serde(default)]
    enabled: BTreeSet<String>,
    #[serde(default)]
    enforced: BTreeSet<String>,
    #[serde(default)]
    commands: Vec<String>,
}

/// The person's decisions, in one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consent {
    file: PathBuf,
}

impl Consent {
    /// `$XDG_CONFIG_HOME/devflow/consent.json`.
    pub fn of_user() -> Consent {
        Consent::at(
            &devflow_engine::home::config_dir().unwrap_or_else(|| PathBuf::from(".devflow-home")),
        )
    }

    /// The file under `folder`.
    pub fn at(folder: &Path) -> Consent {
        Consent {
            file: folder.join(FILE),
        }
    }

    fn kept(&self) -> Kept {
        std::fs::read_to_string(&self.file)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    fn keep(&self, kept: &Kept) -> Result<(), String> {
        let folder = self.file.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(folder).map_err(|err| format!("{}: {err}", folder.display()))?;
        let text = serde_json::to_string_pretty(kept).unwrap_or_default();
        devflow_engine::fsguard::replace(folder, FILE, text.as_bytes())
            .map_err(|err| format!("{}: {err}", self.file.display()))
    }

    /// Whether the person made `ask` in the project at `root`.
    pub fn made(&self, root: &Path, ask: Ask) -> bool {
        let kept = self.kept();
        let key = key_of(root);
        match ask {
            Ask::Enable => kept.enabled.contains(&key),
            Ask::Enforce => kept.enforced.contains(&key),
        }
    }

    /// Keeps, or forgets, that the person made `ask` in the project.
    pub fn remember(&self, root: &Path, ask: Ask, yes: bool) -> Result<(), String> {
        let mut kept = self.kept();
        let key = key_of(root);
        let set = match ask {
            Ask::Enable => &mut kept.enabled,
            Ask::Enforce => &mut kept.enforced,
        };
        if yes {
            set.insert(key);
        } else {
            set.remove(&key);
        }
        self.keep(&kept)
    }

    /// Whether the person confirmed the command with this fingerprint.
    pub fn command_confirmed(&self, print: &str) -> bool {
        self.kept().commands.iter().any(|one| one == print)
    }

    pub fn confirm(&self, print: &str) -> Result<(), String> {
        let mut kept = self.kept();
        if !kept.commands.iter().any(|one| one == print) {
            kept.commands.push(print.to_owned());
        }
        let over = kept.commands.len().saturating_sub(MOST_COMMANDS);
        kept.commands.drain(..over);
        self.keep(&kept)
    }
}

/// A project by its root, resolved.
fn key_of(root: &Path) -> String {
    root.canonicalize()
        .unwrap_or_else(|_| root.to_path_buf())
        .display()
        .to_string()
}

#[cfg(test)]
#[path = "consent_tests.rs"]
mod tests;
