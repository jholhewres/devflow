//! What only the person decides, kept on their machine: devflow switched on
//! in a project, Decisions moved to `enforce` there, a team layer's command
//! confirmed at its commit, and the targets an attack may reach there, with
//! the addresses each name resolved to then. A terminal command with a
//! confirmation writes it (`devflow config set`, `devflow stage confirm`,
//! `devflow setup --attack`), or the person's own answer to the question the
//! MCP server asked them through the client (`elicitation/create`). Each yes
//! is kept with how it came, when, and what it was asked for. A tool's
//! arguments never write it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use devflow_engine::security::{Pins, MOST_PINNED};
use devflow_engine::Ask;
use serde::{Deserialize, Serialize};

const FILE: &str = "consent.json";
/// The newest confirmed commands kept: an old one that comes back is asked again.
const MOST_COMMANDS: usize = 256;
/// The newest yeses kept with how they came.
const MOST_GIVEN: usize = 256;

/// How the person said yes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum How {
    /// On a terminal, to a devflow command.
    Terminal,
    /// To the question the MCP server asked through the client.
    Elicitation,
}

/// One yes: what it allowed in which project, how, when, and what for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Given {
    pub project: String,
    pub what: String,
    pub how: How,
    /// As a run's stamp, UTC.
    pub at: String,
    /// What it was asked for: `attack`, `config set`, `setup`.
    #[serde(rename = "for")]
    pub asked_for: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Kept {
    #[serde(default)]
    enabled: BTreeSet<String>,
    #[serde(default)]
    enforced: BTreeSet<String>,
    #[serde(default)]
    commands: Vec<String>,
    /// By project: the `security.targets` the person confirmed there.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    targets: BTreeMap<String, Vec<String>>,
    /// By project: the addresses each confirmed name resolved to then. A
    /// file from before has none, and its names are confirmed again.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pinned: BTreeMap<String, Pins>,
    /// By project: the `security.stack` the person confirmed there, and the
    /// SHA-256 of its compose file then.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    stacks: BTreeMap<String, (String, String)>,
    /// Each yes, how it came, when and what for; the newest last.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    given: Vec<Given>,
    /// By project: the parts of the attack's question the person answered
    /// there, which are not asked again.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    answered: BTreeMap<String, Vec<String>>,
}

/// The person's decisions, in one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consent {
    file: PathBuf,
    /// A host's own record of the two switches, which it keeps: devflow
    /// switched on, and Decisions on enforce. The file is not read for them.
    switches: Option<[bool; 2]>,
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
            switches: None,
        }
    }

    /// `self`, with the switches as the host keeps them; the rest is still
    /// the file's.
    pub fn switched_by_host(self, enabled: bool, enforce: bool) -> Consent {
        Consent {
            switches: Some([enabled, enforce]),
            ..self
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
        if let Some([enabled, enforce]) = self.switches {
            return match ask {
                Ask::Enable => enabled,
                Ask::Enforce => enforce,
            };
        }
        let kept = self.kept();
        let key = key_of(root);
        match ask {
            Ask::Enable => kept.enabled.contains(&key),
            Ask::Enforce => kept.enforced.contains(&key),
        }
    }

    /// Keeps, or forgets, that the person made `ask` in the project.
    pub fn remember(&self, root: &Path, ask: Ask, yes: bool) -> Result<(), String> {
        if self.switches.is_some() {
            return Ok(());
        }
        let mut kept = self.kept();
        kept.switched(&key_of(root), ask, yes);
        self.keep(&kept)
    }

    /// The targets the person confirmed in the project at `root`.
    pub fn confirmed_targets(&self, root: &Path) -> Vec<String> {
        self.kept()
            .targets
            .remove(&key_of(root))
            .unwrap_or_default()
    }

    /// Keeps `stack` as what the person confirmed in the project: its file
    /// and the SHA-256 of the stack as compose resolved it then; `None`
    /// forgets it.
    pub fn confirm_stack(&self, root: &Path, stack: Option<(&str, &str)>) -> Result<(), String> {
        let mut kept = self.kept();
        let key = key_of(root);
        match stack {
            Some((file, digest)) => {
                kept.stacks
                    .insert(key, (file.to_owned(), digest.to_owned()));
            }
            None => {
                kept.stacks.remove(&key);
            }
        }
        self.keep(&kept)
    }

    /// The stack the person confirmed in the project, and its digest then.
    pub fn confirmed_stack(&self, root: &Path) -> Option<(String, String)> {
        self.kept().stacks.remove(&key_of(root))
    }

    /// The addresses each confirmed name resolved to then, by origin.
    pub fn pinned(&self, root: &Path) -> Pins {
        let mut pins = self.kept().pinned.remove(&key_of(root)).unwrap_or_default();
        for addresses in pins.values_mut() {
            addresses.truncate(MOST_PINNED);
        }
        pins
    }

    /// Keeps `targets` as what the person confirmed in the project, with
    /// the addresses `pins` holds for them: a target left out is no longer
    /// confirmed, and its addresses go.
    pub fn confirm_targets(
        &self,
        root: &Path,
        targets: &[String],
        pins: &Pins,
    ) -> Result<(), String> {
        let mut kept = self.kept();
        kept.targets_confirmed(&key_of(root), targets, pins);
        self.keep(&kept)
    }

    /// Keeps that the person said yes to `what` in the project, `how`, at
    /// `at`, when asked for `asked_for`.
    pub fn record(
        &self,
        root: &Path,
        what: &str,
        how: How,
        asked_for: &str,
        at: std::time::SystemTime,
    ) -> Result<(), String> {
        let mut kept = self.kept();
        kept.recorded(&key_of(root), what, how, asked_for, at);
        self.keep(&kept)
    }

    /// The yeses kept for the project, oldest first.
    pub fn given(&self, root: &Path) -> Vec<Given> {
        let key = key_of(root);
        self.kept()
            .given
            .into_iter()
            .filter(|one| one.project == key)
            .collect()
    }

    /// The parts of the attack's question the person answered in the project.
    pub fn answered(&self, root: &Path) -> BTreeSet<String> {
        self.kept()
            .answered
            .remove(&key_of(root))
            .unwrap_or_default()
            .into_iter()
            .collect()
    }

    /// One answer of the person's in the project, kept in one write: devflow
    /// switched on, the targets they allowed with the addresses shown, each
    /// yes with how it came, and the parts of the question answered.
    pub fn keep_answer(&self, root: &Path, answer: &Answered) -> Result<(), String> {
        let mut kept = self.kept();
        let key = key_of(root);
        if answer.switched_on && self.switches.is_none() {
            kept.switched(&key, Ask::Enable, true);
        }
        if let Some((targets, pins)) = answer.targets {
            kept.targets_confirmed(&key, targets, pins);
        }
        for what in answer.yeses {
            kept.recorded(&key, what, answer.how, answer.asked_for, answer.at);
        }
        kept.parts_answered(&key, answer.parts);
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

/// One answer of the person's, as [`Consent::keep_answer`] keeps it.
pub struct Answered<'a> {
    pub switched_on: bool,
    /// The targets now confirmed, with the addresses shown for them.
    pub targets: Option<(&'a [String], &'a Pins)>,
    /// What each yes allowed, as `given` names it.
    pub yeses: &'a [&'a str],
    pub parts: &'a [String],
    pub how: How,
    pub asked_for: &'a str,
    pub at: std::time::SystemTime,
}

impl Kept {
    fn switched(&mut self, key: &str, ask: Ask, yes: bool) {
        let set = match ask {
            Ask::Enable => &mut self.enabled,
            Ask::Enforce => &mut self.enforced,
        };
        if yes {
            set.insert(key.to_owned());
        } else {
            set.remove(key);
        }
    }

    fn targets_confirmed(&mut self, key: &str, targets: &[String], pins: &Pins) {
        let listed: Vec<String> = targets
            .iter()
            .take(devflow_engine::security::MOST_TARGETS)
            .cloned()
            .collect();
        let origins = devflow_engine::security::origins(&listed);
        let pins: Pins = pins
            .iter()
            .filter(|(origin, _)| origins.contains(origin))
            .map(|(origin, addresses)| {
                let most = addresses.len().min(MOST_PINNED);
                (origin.clone(), addresses[..most].to_vec())
            })
            .collect();
        if listed.is_empty() {
            self.targets.remove(key);
        } else {
            self.targets.insert(key.to_owned(), listed);
        }
        if pins.is_empty() {
            self.pinned.remove(key);
        } else {
            self.pinned.insert(key.to_owned(), pins);
        }
    }

    fn recorded(
        &mut self,
        key: &str,
        what: &str,
        how: How,
        asked_for: &str,
        at: std::time::SystemTime,
    ) {
        self.given.push(Given {
            project: key.to_owned(),
            what: what.to_owned(),
            how,
            at: devflow_engine::runs::stamp(at),
            asked_for: asked_for.to_owned(),
        });
        let over = self.given.len().saturating_sub(MOST_GIVEN);
        self.given.drain(..over);
    }

    /// `parts` answered in the project, the oldest dropped past the most kept.
    fn parts_answered(&mut self, key: &str, parts: &[String]) {
        if parts.is_empty() {
            return;
        }
        let answered = self.answered.entry(key.to_owned()).or_default();
        for part in parts {
            answered.retain(|one| one != part);
            answered.push(part.clone());
        }
        let over = answered.len().saturating_sub(MOST_COMMANDS);
        answered.drain(..over);
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
