//! The project's devflow.yaml: what it says, and the text a change to it
//! leaves. A change of one word is made in place, so the person's own
//! comments and layout stay; anything larger lays the file out again.

use std::path::Path;

use crate::config::{self, Config, Invalid};
use crate::locate::Origin;
use crate::node::{self, Node, Value};
use crate::preset::Change;
use crate::render::{render, scalar};

/// The folder devflow keeps in a project, relative to its root.
pub const DIR: &str = ".devflow";

/// Where devpit's Devflow keeps the same folder: read and written where it
/// is, so a project already on it needs no migration.
pub const LEGACY: &str = ".devpit/devflow";

/// The configuration a setup writes, relative to the project's root.
pub const FILE: &str = ".devflow/devflow.yaml";

/// The folder `root` keeps devflow in: devpit's when its configuration is
/// the one that applies, else [`DIR`].
pub fn dir(root: &Path) -> &'static str {
    match crate::locate::config_in(root) {
        Some(found) if found.origin == Origin::Devpit => LEGACY,
        _ => DIR,
    }
}

/// The configuration that applies to `root`, relative to it: `devflow.yaml`,
/// `.devflow/devflow.yaml` or devpit's, else where a setup writes one.
pub fn file(root: &Path) -> String {
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
}

impl Layout {
    /// `root`'s, as [`dir`] and [`file`] find it.
    pub fn of(root: &Path) -> Layout {
        Layout {
            dir: dir(root),
            file: file(root),
        }
    }
}

impl Default for Layout {
    /// A new project's: `.devflow/` and `.devflow/devflow.yaml`.
    fn default() -> Layout {
        Layout {
            dir: DIR,
            file: FILE.to_owned(),
        }
    }
}

/// `config` as `root` keeps it: a project in devpit's folder that never
/// moved its E2E specs keeps them in that folder.
pub fn relocated(root: &Path, mut config: Config) -> Config {
    if dir(root) == LEGACY && config.stages.execution.e2e_dir == config::E2E_DIR {
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
    match config::parse(&text) {
        Ok(config) => State::Valid(text, Box::new(relocated(root, config))),
        Err(invalid) => State::Invalid(Some(text), invalid),
    }
}

/// The text that says `after`, made from `text` by `changed`. Answers
/// whether the file was laid out again, which loses the person's own
/// comments.
pub fn rewritten(text: Option<&str>, changed: &[Change], after: &Config) -> (String, bool) {
    if let Some(edited) = text.and_then(|text| in_place(text, changed)) {
        if config::parse(&edited).as_ref() == Ok(after) {
            return (edited, false);
        }
    }
    (render(after), true)
}

/// The JSON form of a file that parses as YAML, valid or not: what a change
/// to an invalid file starts from.
pub(crate) fn as_json(text: &str) -> Option<serde_json::Value> {
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

/// `text` with each changed word replaced where it stands, or `None` when a
/// change is not one plain word already in the text.
fn in_place(text: &str, changed: &[Change]) -> Option<String> {
    let tree = node::from_yaml(text).ok()?;
    let mut lines: Vec<String> = text.split_inclusive('\n').map(str::to_owned).collect();
    for change in changed {
        let word = match &change.after {
            serde_json::Value::Bool(yes) => yes.to_string(),
            serde_json::Value::String(text) => scalar(text),
            _ => return None,
        };
        let found = find(&tree, &change.path)?;
        let (Value::Scalar(old, true), Some(at)) = (&found.value, found.at) else {
            return None;
        };
        let line = lines.get_mut(at.line.checked_sub(1)?)?;
        let start = line
            .char_indices()
            .nth(at.col)
            .map(|(byte, _)| byte)
            .unwrap_or(line.len());
        if !line[start..].starts_with(old.as_str()) {
            return None;
        }
        line.replace_range(start..start + old.len(), &word);
    }
    Some(lines.concat())
}

/// The node at a dotted path.
fn find<'a>(tree: &'a Node, path: &str) -> Option<&'a Node> {
    path.split('.').try_fold(tree, |at, part| match &at.value {
        Value::Map(items) => items
            .iter()
            .find(|(key, _)| key.name == part)
            .map(|(_, node)| node),
        Value::Seq(items) => match part.parse::<usize>() {
            Ok(index) => items.get(index),
            // A stage of version 2's list, by its name.
            Err(_) => items.iter().find(|item| stage_named(item) == Some(part)),
        },
        _ => None,
    })
}

/// The name an item of a list of stages has: what follows the last `/` of `uses`.
fn stage_named(item: &Node) -> Option<&str> {
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
