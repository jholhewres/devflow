//! The project's devflow.yaml: what it says, and the text a change to it
//! leaves. A change is made in place, so the person's own comments, layout
//! and the fields devflow does not read stay; only a file that cannot be
//! edited there is laid out again.

use std::path::Path;

use crate::config::{self, Config, Invalid};
use crate::locate::Origin;
use crate::node::{self, Node, Value};
use crate::preset::Change;
use crate::render::render_in;

/// The folder devflow keeps in a project, relative to its root.
pub const DIR: &str = ".devflow";

/// Where devpit's Devflow keeps the same folder: read and written where it
/// is, so a project already on it needs no migration.
pub const LEGACY: &str = ".devpit/devflow";

/// The configuration a setup writes, relative to the project's root.
pub const FILE: &str = ".devflow/devflow.yaml";

static PINNED: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();

/// Every project keeps devflow in `dir` from now on, whatever it holds: a
/// host with a folder of its own (devpit's [`LEGACY`]) says so once, before
/// the first read. A second call is refused.
pub fn pin(dir: &'static str) -> Result<(), String> {
    PINNED
        .set(dir)
        .map_err(|_| "devflow's folder is already pinned".to_owned())
}

/// The folder a host pinned, if one did.
pub fn pinned() -> Option<&'static str> {
    PINNED.get().copied()
}

/// The folder a project with no configuration yet is set up in.
pub fn default_dir() -> &'static str {
    pinned().unwrap_or(DIR)
}

/// The configuration a setup writes, relative to the project's root: [`FILE`]
/// or the pinned folder's.
pub fn default_file() -> String {
    format!("{}/{}", default_dir(), crate::locate::FILE)
}

/// The folder `root` keeps devflow in: the pinned one, else devpit's when its
/// configuration is the one that applies, else [`DIR`].
pub fn dir(root: &Path) -> &'static str {
    if let Some(pinned) = pinned() {
        return pinned;
    }
    match crate::locate::config_in(root) {
        Some(found) if found.origin == Origin::Devpit => LEGACY,
        _ => DIR,
    }
}

/// The configuration that applies to `root`, relative to it: `devflow.yaml`,
/// `.devflow/devflow.yaml` or devpit's, else where a setup writes one.
pub fn file(root: &Path) -> String {
    if let Some(pinned) = pinned() {
        return format!("{pinned}/{}", crate::locate::FILE);
    }
    match crate::locate::config_in(root).map(|found| found.origin) {
        Some(Origin::Root) => crate::locate::FILE.to_owned(),
        Some(Origin::Devpit) => crate::locate::DEVPIT.to_owned(),
        Some(Origin::Folder) | None => FILE.to_owned(),
    }
}

/// Where a project keeps devflow: its folder and its configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub dir: &'static str,
    pub file: String,
    /// The words of the files written there.
    pub dialect: &'static crate::Dialect,
}

impl Layout {
    /// `root`'s, as [`dir`] and [`file`] find it.
    pub fn of(root: &Path) -> Layout {
        Layout {
            dir: dir(root),
            file: file(root),
            dialect: &crate::Dialect::DEVFLOW,
        }
    }
}

impl Default for Layout {
    /// A new project's: `.devflow/` and `.devflow/devflow.yaml`, or the
    /// pinned folder's.
    fn default() -> Layout {
        Layout {
            dir: default_dir(),
            file: default_file(),
            dialect: &crate::Dialect::DEVFLOW,
        }
    }
}

/// `config` as `root` keeps it: a project in devpit's folder that never
/// moved its E2E specs keeps them in that folder.
pub fn relocated(root: &Path, config: Config) -> Config {
    relocated_in(dir(root), config)
}

/// [`relocated`], for a project that keeps devflow in `dir`.
fn relocated_in(dir: &str, mut config: Config) -> Config {
    if pinned().is_none() && dir == LEGACY && config.stages.execution.e2e_dir == config::E2E_DIR {
        config.stages.execution.e2e_dir = config::LEGACY_E2E_DIR.to_owned();
    }
    config
}

/// The most of devflow.yaml read, checked before reading.
pub const MOST_BYTES: u64 = 256 * 1024;

/// What the project's devflow.yaml says.
#[derive(Debug, Clone, PartialEq)]
pub enum State {
    Missing,
    /// The text when it could be read, and why it is refused.
    Invalid(Option<String>, Invalid),
    /// Boxed: a configuration is many times the size of a refusal.
    Valid(String, Box<Config>),
}

/// The state of `root`'s devflow.yaml, read through symlinks and only from
/// inside the project.
pub fn read(root: &Path) -> State {
    read_in(&crate::Dialect::DEVFLOW, root)
}

/// [`read`], an invalid file told in `dialect`'s words.
pub fn read_in(dialect: &crate::Dialect, root: &Path) -> State {
    let file = file(root);
    let path = root.join(&file);
    if path.symlink_metadata().is_err() {
        return State::Missing;
    }
    let refused = |why: &str| State::Invalid(None, Invalid::at(None, "", why));
    let Ok(resolved) = crate::fsguard::resolve(root, &file) else {
        return refused("devflow.yaml leads outside the project");
    };
    match std::fs::metadata(&resolved) {
        Ok(meta) if !meta.is_file() => return refused("devflow.yaml is not a file"),
        Ok(meta) if meta.len() > MOST_BYTES => {
            return refused("devflow.yaml is larger than 256 KB, which no setting needs")
        }
        Ok(_) => {}
        Err(_) => return refused("devflow.yaml could not be read"),
    }
    let Ok(text) = std::fs::read_to_string(&resolved) else {
        return refused("devflow.yaml is not UTF-8 text");
    };
    match config::parse_in(dialect, &text) {
        Ok(config) => State::Valid(text, Box::new(relocated(root, config))),
        Err(invalid) => State::Invalid(Some(text), invalid),
    }
}

/// The text that says `after`, made from `text` by `changed`. Answers
/// whether the file was laid out again, which loses the person's own
/// comments.
pub fn rewritten(text: Option<&str>, changed: &[Change], after: &Config) -> (String, bool) {
    rewritten_in(&crate::Dialect::DEVFLOW, text, changed, after)
}

/// [`rewritten`], a file laid out again in `dialect`'s comments.
pub fn rewritten_in(
    dialect: &crate::Dialect,
    text: Option<&str>,
    changed: &[Change],
    after: &Config,
) -> (String, bool) {
    if let Some(edited) = text.and_then(|text| in_place(text, changed)) {
        if config::parse_in(dialect, &edited).as_ref() == Ok(after) {
            return (edited, false);
        }
    }
    (render_in(dialect, after), true)
}

/// [`rewritten_in`] for a project laid out as `layout`: the edited text is
/// read as the project's file is, relocated, before it is compared.
pub fn rewritten_at(
    layout: &Layout,
    text: Option<&str>,
    changed: &[Change],
    after: &Config,
) -> (String, bool) {
    if let Some(edited) = text.and_then(|text| in_place(text, changed)) {
        let read = config::parse_in(layout.dialect, &edited)
            .map(|config| relocated_in(layout.dir, config));
        if read.as_ref() == Ok(after) {
            return (edited, false);
        }
    }
    (render_in(layout.dialect, after), true)
}

/// The JSON form of a file that parses as YAML, valid or not: what a change
/// to an invalid file starts from.
pub fn as_json(text: &str) -> Option<serde_json::Value> {
    node::from_yaml(text).ok().map(|tree| json_of(&tree))
}

fn json_of(node: &Node) -> serde_json::Value {
    use serde_json::Value as Json;
    match &node.value {
        Value::Null => Json::Null,
        Value::Scalar(text, plain) => match (text.as_str(), plain) {
            ("true", true) => Json::Bool(true),
            ("false", true) => Json::Bool(false),
            (number, true) if number.parse::<u64>().is_ok() => {
                Json::Number(number.parse::<u64>().unwrap_or_default().into())
            }
            _ => Json::String(text.clone()),
        },
        Value::Seq(items) => Json::Array(items.iter().map(json_of).collect()),
        Value::Map(items) => Json::Object(
            items
                .iter()
                .map(|(key, node)| (key.name.clone(), json_of(node)))
                .collect(),
        ),
    }
}

/// `text` with each change made where it stands: a word swapped, a key
/// added or removed, a value replaced; `None` when one cannot be.
fn in_place(text: &str, changed: &[Change]) -> Option<String> {
    changed.iter().try_fold(text.to_owned(), |text, change| {
        crate::edit::set(&text, &change.path, &change.after)
    })
}

/// The name an item of a list of stages has: what follows the last `/` of `uses`.
pub(crate) fn stage_named(item: &Node) -> Option<&str> {
    let Value::Map(fields) = &item.value else {
        return None;
    };
    let (_, uses) = fields.iter().find(|(key, _)| key.name == "uses")?;
    let Value::Scalar(uses, _) = &uses.value else {
        return None;
    };
    Some(uses.rsplit('/').next().unwrap_or(uses))
}

#[cfg(test)]
#[path = "folder_tests.rs"]
mod tests;
