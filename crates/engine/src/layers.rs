//! Devflow in layers: devpit's built-in defaults, then the person's own
//! (`<devpit home>/devflow/devflow.yaml`), then each team or company layer
//! the project `extends`, then the project's own file. A later layer wins,
//! except where an earlier one locked a field: the project may not weaken
//! what its team locked.
//!
//! A team layer is somebody else's repository. It is read only at the commit
//! `.devpit/devflow/devflow.lock` pins, each file checked against the hash
//! the person approved; a ref that moved applies nothing new until the
//! person approves what changed, and nothing in it runs when it is fetched.
//! Only the project says whether its Devflow is on and what it extends.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::git::pinned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::config::{self, Config, Extend, Invalid};
use crate::folder;

/// The lockfile, relative to the project's root. Committed with the project.
pub const LOCK: &str = ".devflow/devflow.lock";

/// [`LOCK`] in `root`'s own folder.
pub fn lock(root: &Path) -> String {
    format!("{}/devflow.lock", crate::folder::dir(root))
}
/// A layer's own settings, at the root of its repository.
pub const LAYER_FILE: &str = "devflow.yaml";
/// The most of a lockfile or a personal layer read, checked before reading.
const MOST_READ: u64 = 256 * 1024;

/// What the person approved of each layer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lock {
    pub extends: Vec<Locked>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Locked {
    pub git: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub commit: String,
    /// Every file of the layer at `commit`, and its SHA-256.
    pub files: BTreeMap<String, String>,
}

/// Where devflow keeps the layers that are not the project's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Home {
    pub personal: PathBuf,
    pub teams: PathBuf,
}

impl Home {
    /// The layers under one folder, `<root>/devflow` and `<root>/devflow/teams`,
    /// as devpit's home lays them out.
    pub fn under(root: &Path) -> Home {
        let personal = root.join("devflow");
        Home {
            teams: personal.join("teams"),
            personal,
        }
    }

    /// The person's: their XDG config and cache folders.
    pub fn of_user() -> Option<Home> {
        Some(Home {
            personal: crate::home::personal(&crate::home::config_dir()?),
            teams: crate::home::teams(&crate::home::cache_dir()?),
        })
    }
}

/// The name a layer's own stages are used under: the owner in its address,
/// `acme` for `git@bitbucket.org:acme/devpit-devflow.git`.
pub fn name_of(git: &str) -> String {
    let trimmed = git.trim_end_matches('/');
    let trimmed = trimmed.strip_suffix(".git").unwrap_or(trimmed);
    let parts: Vec<&str> = trimmed
        .split(['/', ':', '\\'])
        .filter(|part| !part.is_empty())
        .collect();
    let owner = match parts.as_slice() {
        [.., owner, _] => owner,
        [only] => only,
        [] => "team",
    };
    let name: String = owner
        .to_ascii_lowercase()
        .chars()
        .map(|one| {
            if one.is_ascii_alphanumeric() || one == '_' {
                one
            } else {
                '-'
            }
        })
        .collect();
    let name = name.trim_matches('-').to_owned();
    if config::is_name(&name) {
        name
    } else {
        "team".to_owned()
    }
}

/// The lockfile, or an empty one when there is none.
pub fn read_lock(root: &Path) -> Result<Lock, String> {
    let lock = lock(root);
    if root.join(&lock).symlink_metadata().is_err() {
        return Ok(Lock::default());
    }
    let resolved = crate::fsguard::resolve(root, &lock)
        .map_err(|_| "devflow.lock leads outside the project".to_owned())?;
    let file = std::fs::File::open(resolved).map_err(|err| format!("devflow.lock: {err}"))?;
    let raw = crate::fsguard::read_within(file, MOST_READ)
        .map_err(|err| format!("devflow.lock: {err}"))?
        .ok_or("devflow.lock is larger than 256 KB")?;
    serde_json::from_slice(&raw).map_err(|err| format!("devflow.lock does not read: {err}"))
}

/// Writes the lockfile, inside the project. devpit never commits it.
pub fn write_lock(root: &Path, lock: &Lock) -> Result<(), String> {
    crate::setup::folders(root, crate::folder::dir(root))?;
    let file = self::lock(root);
    let path = crate::fsguard::resolve_new(root, &file).map_err(|err| format!("{file}: {err}"))?;
    let text = serde_json::to_string_pretty(lock).unwrap_or_default();
    std::fs::write(path, format!("{text}\n")).map_err(|err| format!("{file}: {err}"))
}

/// How one layer the project extends stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Standing {
    pub name: String,
    pub git: String,
    /// The ref devflow.yaml names.
    pub wanted: String,
    /// What the lockfile pins, when it pins this layer.
    pub locked_ref: Option<String>,
    pub commit: Option<String>,
    /// `applied`; `approve`, a ref the person has not approved (what was
    /// approved before still applies); or `fetch`, a pinned commit this
    /// machine does not have yet.
    pub state: &'static str,
}

/// A layer that applies: its files at the pinned commit, each checked
/// against the hash the person approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Team {
    pub name: String,
    pub git: String,
    pub commit: String,
    cache: PathBuf,
    files: BTreeMap<String, String>,
}

impl Team {
    /// A file of the layer as approved; none when the layer has no such file.
    pub fn read(&self, path: &str) -> Result<Option<String>, String> {
        let Some(digest) = self.files.get(path) else {
            return Ok(None);
        };
        let bytes = pinned::read(&self.cache, &self.commit, path, pinned::MOST_FILE_BYTES)
            .map_err(|err| format!("{}'s {path}: {err}", self.name))?;
        if pinned::digest(&bytes) != *digest {
            return Err(format!(
                "{}'s {path} is not what was approved: its hash changed",
                self.name
            ));
        }
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| format!("{}'s {path} is not UTF-8 text", self.name))
    }

    /// The pinned commit's files, with what each one was approved as.
    pub fn files(&self) -> &BTreeMap<String, String> {
        &self.files
    }
}

/// Each layer the project extends: the ones that apply, and how each stands.
pub fn teams(
    root: &Path,
    extends: &[Extend],
    home: &Home,
) -> Result<(Vec<Team>, Vec<Standing>), String> {
    let lock = read_lock(root)?;
    let (mut applied, mut said) = (Vec::new(), Vec::new());
    for layer in extends {
        let name = name_of(&layer.git);
        let locked = lock.extends.iter().find(|one| one.git == layer.git);
        let cache = pinned::cache_for(&home.teams, &layer.git);
        let held = locked.is_some_and(|locked| pinned::holds(&cache, &locked.commit));
        let state = match locked {
            None => "approve",
            Some(_) if !held => "fetch",
            Some(locked) if locked.reference != layer.reference => "approve",
            Some(_) => "applied",
        };
        if let (Some(locked), true) = (locked, held) {
            applied.push(Team {
                name: name.clone(),
                git: layer.git.clone(),
                commit: locked.commit.clone(),
                cache: cache.clone(),
                files: locked.files.clone(),
            });
        }
        said.push(Standing {
            name,
            git: layer.git.clone(),
            wanted: layer.reference.clone(),
            locked_ref: locked.map(|one| one.reference.clone()),
            commit: locked.map(|one| one.commit.clone()),
            state,
        });
    }
    Ok((applied, said))
}

/// The configuration the flow runs on, and where each layer stands.
#[derive(Debug, Clone, PartialEq)]
pub struct Layered {
    pub config: Config,
    pub teams: Vec<Standing>,
    pub applied: Vec<Team>,
    /// The layer the list of stages came from: `project`, `personal`, a
    /// team's name, or `built-in`.
    pub stages_from: String,
    /// What the layers above the project locked, by dotted path.
    pub locks: Vec<String>,
}

/// A layer above the project, read as JSON once it reads as a devflow.yaml.
fn upper(text: &str, what: &str) -> Result<Value, Invalid> {
    config::parse(text)
        .map_err(|invalid| Invalid::at(None, &invalid.field, &format!("{what}: {invalid}")))?;
    let mut json = folder::as_json(text).unwrap_or_default();
    if let Some(fields) = json.as_object_mut() {
        for key in ["version", "enabled", "extends"] {
            fields.remove(key);
        }
    }
    Ok(json)
}

/// The person's own layer, when they keep one.
fn personal(home: &Home) -> Result<Option<Value>, Invalid> {
    let refused = |why: &str| Invalid::at(None, "", &format!("your own devflow.yaml {why}"));
    if home.personal.join(LAYER_FILE).symlink_metadata().is_err() {
        return Ok(None);
    }
    let path = crate::fsguard::resolve(&home.personal, LAYER_FILE)
        .map_err(|_| refused("leads outside its folder"))?;
    let file = std::fs::File::open(path).map_err(|_| refused("could not be read"))?;
    let raw = crate::fsguard::read_within(file, MOST_READ)
        .map_err(|_| refused("could not be read"))?
        .ok_or_else(|| refused("is larger than 256 KB"))?;
    let text = String::from_utf8(raw).map_err(|_| refused("is not UTF-8 text"))?;
    upper(&text, "your own devflow.yaml").map(Some)
}

/// `merged` with `layer` over it: maps field by field, anything else whole.
fn merge(merged: &mut Value, layer: &Value) {
    match (merged, layer) {
        (Value::Object(into), Value::Object(from)) => {
            for (key, value) in from {
                match into.get_mut(key) {
                    Some(there) if there.is_object() && value.is_object() => merge(there, value),
                    _ => {
                        into.insert(key.clone(), value.clone());
                    }
                }
            }
        }
        (into, from) => *into = from.clone(),
    }
}

/// What a dotted path picks: one value, or the items of a list it names by
/// a stage's name, a reviewer's persona or a check's name.
#[derive(Debug, PartialEq)]
enum Picked<'a> {
    One(&'a Value),
    Items(Vec<&'a Value>),
}

fn keyed(item: &Value, part: &str) -> bool {
    crate::preset::stage_name(item) == Some(part)
        || ["persona", "name"]
            .iter()
            .any(|key| item.get(*key).and_then(Value::as_str) == Some(part))
}

fn pick<'a>(value: &'a Value, path: &str) -> Option<Picked<'a>> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut at = value;
    for (index, part) in parts.iter().enumerate() {
        at = match at {
            Value::Object(fields) => fields.get(*part)?,
            Value::Array(items) => match part.parse::<usize>() {
                Ok(slot) => items.get(slot)?,
                Err(_) => {
                    let matching: Vec<&Value> =
                        items.iter().filter(|item| keyed(item, part)).collect();
                    if index + 1 == parts.len() || matching.len() != 1 {
                        return Some(Picked::Items(matching));
                    }
                    matching[0]
                }
            },
            _ => return None,
        };
    }
    Some(Picked::One(at))
}

/// Whether `merged` keeps what `upper` says at the locked `path`.
fn held(path: &str, upper: &Value, merged: &Value) -> Result<(), String> {
    match (pick(upper, path), pick(merged, path)) {
        (None, _) => Ok(()),
        (Some(Picked::Items(want)), Some(Picked::Items(have)))
            if want.iter().all(|one| have.contains(one)) =>
        {
            Ok(())
        }
        (Some(Picked::One(want)), Some(Picked::One(have))) if want == have => Ok(()),
        (Some(Picked::Items(want)), _) if want.is_empty() => Ok(()),
        _ => Err("the project cannot change or remove it".to_owned()),
    }
}

fn locked_in(layer: &Value) -> Vec<String> {
    layer
        .get("locked")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// The project's devflow.yaml `text` read over its layers. Refused, with the
/// field, when the project changes what a layer locked.
pub fn layered(root: &Path, text: &str, home: &Home) -> Result<Layered, Invalid> {
    let own = config::parse(text)?;
    let (applied, teams) =
        teams(root, &own.extends, home).map_err(|why| Invalid::at(None, "extends", &why))?;
    let mut uppers: Vec<(String, Value)> = Vec::new();
    if let Some(json) = personal(home)? {
        uppers.push(("your own layer".to_owned(), json));
    }
    for team in &applied {
        let read = team
            .read(LAYER_FILE)
            .map_err(|why| Invalid::at(None, "extends", &why))?;
        if let Some(text) = read {
            let what = format!("{}'s devflow.yaml", team.name);
            uppers.push((team.name.clone(), upper(&text, &what)?));
        }
    }
    let project = folder::as_json(text).unwrap_or_default();
    let mut merged = Value::Object(Map::new());
    let mut stages_from = "built-in".to_owned();
    for (name, layer) in &uppers {
        if layer.get("stages").is_some() {
            stages_from.clone_from(name);
        }
        merge(&mut merged, layer);
    }
    if project.get("stages").is_some() {
        stages_from = "project".to_owned();
    }
    merge(&mut merged, &project);
    for (name, layer) in &uppers {
        for path in locked_in(layer) {
            held(&path, layer, &merged)
                .map_err(|why| Invalid::at(None, &path, &format!("locked by {name}: {why}")))?;
        }
    }
    let mut locks: Vec<String> = uppers
        .iter()
        .flat_map(|(_, layer)| locked_in(layer))
        .collect();
    locks.dedup();
    // The project's own locks stay its own: a change rewrites its file from
    // this configuration, and a team's lock is not the project's to say.
    if let Some(fields) = merged.as_object_mut() {
        fields.remove("locked");
        if !own.locked.is_empty() {
            fields.insert("locked".to_owned(), Value::from(own.locked.clone()));
        }
    }
    let config = folder::relocated(root, config::from_json(&merged)?);
    Ok(Layered {
        config,
        teams,
        applied,
        stages_from,
        locks,
    })
}

/// What a project with no devflow.yaml of its own runs a stage on demand
/// with: the person's layer over the defaults.
pub fn personal_only(home: &Home) -> Result<Config, Invalid> {
    let mut merged = serde_json::json!({ "version": config::VERSION });
    if let Some(layer) = personal(home)? {
        merge(&mut merged, &layer);
    }
    if let Some(fields) = merged.as_object_mut() {
        fields.remove("locked");
    }
    config::from_json(&merged)
}

#[cfg(test)]
#[path = "layers_tests.rs"]
mod tests;
