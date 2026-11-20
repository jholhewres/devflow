//! The two starting points of a setup, and a change of one field.
//!
//! `recommended` is the configuration devpit would choose from what it
//! detected; `custom` is the schema's defaults with nothing chosen. Either is
//! then adjusted by dotted paths — the answers to what detection left open —
//! and the result is checked by the same reader as a file.

use serde::Serialize;
use serde_json::Value;

use crate::config::{self, Agent, Check, Config, Evidence, Invalid, Mode, Reviewer};
use crate::detect::Detected;

/// The persona the recommended reviewer takes.
pub const SECURITY: &str = "devflow-security";

/// The checks the recommended preset runs once for a release, not for each
/// item: the E2E suites, too long to repeat on every evidence run.
pub const RELEASE: [&str; 2] = ["e2e", "e2e-suite"];

/// The agent CLIs a reviewer is picked from, in order: each one a headless
/// reader can be held to reading, as [`crate::agents::read_only`] says.
fn reviewers() -> impl Iterator<Item = Agent> {
    Agent::ALL.iter().copied().filter(|agent| {
        crate::agents::Cli::of(agent.word())
            .is_some_and(|cli| crate::agents::read_only(cli).is_ok())
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    Recommended,
    Custom,
}

impl Preset {
    pub fn of(word: &str) -> Option<Self> {
        match word {
            "recommended" => Some(Preset::Recommended),
            "custom" => Some(Preset::Custom),
            _ => None,
        }
    }

    pub fn word(self) -> &'static str {
        match self {
            Preset::Recommended => "recommended",
            Preset::Custom => "custom",
        }
    }
}

/// A check the setup proposes, with where its command was found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Proposed {
    pub name: String,
    pub run: String,
    pub report: config::Report,
    pub source: Option<String>,
    pub evidence: Vec<Evidence>,
}

/// The checks devpit would configure: the first test command, the E2E check,
/// the first lint and typecheck commands it found, and `unit-<folder>` for a
/// module in a subfolder — each only when it can run here. With Playwright
/// the E2E check runs Devflow's specs through the config devpit writes,
/// keeping screenshots and video; the project's own E2E command, when there
/// is one, is still called, as `e2e-suite`.
pub fn checks(detected: &Detected) -> Vec<Proposed> {
    let found = |name: &str, found: &crate::detect::Found, evidence: Vec<Evidence>| Proposed {
        name: name.to_owned(),
        run: found.command.clone(),
        report: found.report,
        source: Some(found.source.clone()),
        evidence,
    };
    let own_e2e = first(&detected.e2e);
    let devflows = detected.e2e_tools.iter().find_map(|tool| {
        Some(Proposed {
            name: "e2e".to_owned(),
            run: tool.run.clone()?,
            report: config::Report::Junit,
            source: Some(tool.source.clone()),
            evidence: vec![Evidence::Screenshots, Evidence::Video],
        })
    });
    let e2e = match devflows {
        Some(devflows) => [
            Some(devflows),
            own_e2e.map(|own| found("e2e-suite", own, Vec::new())),
        ],
        None => {
            let screenshots = if detected.e2e_tools.is_empty() {
                Vec::new()
            } else {
                vec![Evidence::Screenshots]
            };
            [own_e2e.map(|own| found("e2e", own, screenshots)), None]
        }
    };
    let nested = detected
        .nested
        .iter()
        .filter(|one| one.test.unavailable.is_none())
        .filter_map(|one| Some(found(&nested_name(&one.folder)?, &one.test, Vec::new())));
    let mut proposed: Vec<Proposed> =
        std::iter::once(first(&detected.test).map(|one| found("unit", one, Vec::new())))
            .chain(e2e)
            .chain([
                first(&detected.lint).map(|one| found("lint", one, Vec::new())),
                first(&detected.typecheck).map(|one| found("typecheck", one, Vec::new())),
            ])
            .flatten()
            .chain(nested)
            .collect();
    let mut seen = Vec::new();
    proposed.retain(|one| {
        let fresh = !seen.contains(&one.name);
        seen.push(one.name.clone());
        fresh
    });
    proposed
}

/// The first of `all` that can run here.
fn first(all: &[crate::detect::Found]) -> Option<&crate::detect::Found> {
    all.iter().find(|one| one.unavailable.is_none())
}

/// `unit-<folder>`, the folder's `/` and `.` as `-`: a check's name.
pub(crate) fn nested_name(folder: &str) -> Option<String> {
    let name = format!(
        "unit-{}",
        folder.to_ascii_lowercase().replace(['/', '.'], "-")
    );
    config::is_name(&name).then_some(name)
}

/// What `preset` starts from, given what was detected.
pub fn starting(preset: Preset, detected: &Detected) -> Config {
    let mut config = Config::default();
    // Said in the file, so where the plan goes is there to change.
    config.stages.plan.publish = Some(config::Publish::Board);
    if preset == Preset::Custom {
        return config;
    }
    let (release, checks): (Vec<Check>, Vec<Check>) = checks(detected)
        .into_iter()
        .map(|proposed| Check {
            evidence: proposed.evidence,
            name: proposed.name,
            run: proposed.run,
            report: proposed.report,
            requires: None,
            exclusive: None,
        })
        .partition(|check| RELEASE.contains(&check.name.as_str()));
    config.stages.execution.checks = checks;
    config.stages.execution.release = release;
    let reviewer = reviewers().find(|agent| {
        detected
            .clis
            .iter()
            .any(|cli| cli.name == *agent && cli.installed && cli.signed_in != Some(false))
    });
    config.review.reviewers = reviewer
        .map(|agent| Reviewer {
            agent,
            persona: SECURITY.to_owned(),
            model: None,
        })
        .into_iter()
        .collect();
    config.review.scale = Some(crate::scale::Scale::default());
    config.decisions.use_ = detected.decisions_key && !detected.decisions_opted_out;
    config.decisions.mode = Mode::Shadow;
    config
}

/// `config` with the value at the dotted `path` replaced. Checked like a file.
pub fn with_set(config: &Config, path: &str, value: &Value) -> Result<Config, Invalid> {
    with_set_in(&crate::Dialect::DEVFLOW, config, path, value)
}

/// [`with_set`], refused in `dialect`'s words.
pub fn with_set_in(
    dialect: &crate::Dialect,
    config: &Config,
    path: &str,
    value: &Value,
) -> Result<Config, Invalid> {
    let mut whole = config.to_json();
    for (path, value) in attack_alias(path, value) {
        whole = set_path(dialect, whole, &path, &value)?;
    }
    config::from_json_in(dialect, &whole)
}

/// A change to `review.attack`, the older name, made to `stages.attack`:
/// a word is its `run`, a map its `run` and `model`.
fn attack_alias(path: &str, value: &Value) -> Vec<(String, Value)> {
    let Some(rest) = path.trim().strip_prefix("review.attack") else {
        return vec![(path.to_owned(), value.clone())];
    };
    let stage = format!("stages.{}", config::ATTACK);
    match (rest, value) {
        ("", Value::Object(fields)) => fields
            .iter()
            .map(|(key, said)| (format!("{stage}.{key}"), said.clone()))
            .collect(),
        ("", _) => vec![(format!("{stage}.run"), value.clone())],
        (rest, _) if rest.starts_with('.') => vec![(format!("{stage}{rest}"), value.clone())],
        _ => vec![(path.to_owned(), value.clone())],
    }
}

/// `whole` with the value at the dotted `path` replaced: a field, a list item
/// by index (one past the end adds one), or a whole map or list.
pub(crate) fn set_path(
    dialect: &crate::Dialect,
    mut whole: Value,
    path: &str,
    value: &Value,
) -> Result<Value, Invalid> {
    let parts: Vec<&str> = path.split('.').map(str::trim).collect();
    if parts.iter().any(|part| part.is_empty()) {
        return Err(Invalid::at(None, path, "a path is fields joined by dots"));
    }
    if parts == ["version"] {
        return Err(Invalid::at(
            None,
            path,
            &format!("the version is {}'s to write", dialect.product),
        ));
    }
    if !whole.is_object() {
        whole = Value::Object(Default::default());
    }
    let mut at = &mut whole;
    for (index, part) in parts.iter().enumerate() {
        let last = index + 1 == parts.len();
        at = match at {
            Value::Object(fields) => {
                if last {
                    fields.insert((*part).to_owned(), value.clone());
                    break;
                }
                fields
                    .entry((*part).to_owned())
                    .or_insert_with(|| Value::Object(Default::default()))
            }
            Value::Array(items) => {
                let shown = parts[..index].join(".");
                let slot = match part.parse::<usize>() {
                    Ok(slot) => Some(slot),
                    Err(_) => only_named(items, part).map_err(|places| {
                        Invalid::at(
                            None,
                            &parts[..=index].join("."),
                            &twice(&shown, part, &places),
                        )
                    })?,
                };
                let Some(slot) = slot.filter(|slot| *slot <= items.len()) else {
                    if part.parse::<usize>().is_err() {
                        let what = if items.iter().any(|item| item.get("uses").is_some()) {
                            "stage"
                        } else {
                            "item"
                        };
                        return Err(Invalid::at(
                            None,
                            &parts[..=index].join("."),
                            &format!("{shown} has no {what} called `{part}`"),
                        ));
                    }
                    return Err(Invalid::at(
                        None,
                        path,
                        &format!(
                            "{shown} has {} items: index 0 to {}",
                            items.len(),
                            items.len()
                        ),
                    ));
                };
                if slot == items.len() {
                    items.push(Value::Object(Default::default()));
                }
                if last {
                    items[slot] = value.clone();
                    break;
                }
                &mut items[slot]
            }
            _ => {
                return Err(Invalid::at(
                    None,
                    path,
                    &format!("{} holds a value, not fields", parts[..index].join(".")),
                ))
            }
        };
    }
    Ok(whole)
}

/// The value at a dotted path, null where nothing is; or why a name in it
/// is two items of a list, which a read refuses as a write does.
pub fn find<'a>(whole: &'a Value, path: &str) -> Result<&'a Value, String> {
    let parts: Vec<&str> = path.split('.').map(str::trim).collect();
    let mut at = whole;
    for (index, part) in parts.iter().enumerate() {
        let next = match at {
            Value::Object(fields) => fields.get(*part),
            Value::Array(items) => {
                let slot = match part.parse::<usize>() {
                    Ok(slot) => Some(slot),
                    Err(_) => only_named(items, part)
                        .map_err(|places| twice(&parts[..index].join("."), part, &places))?,
                };
                slot.and_then(|slot| items.get(slot))
            }
            _ => None,
        };
        match next {
            Some(next) => at = next,
            None => return Ok(&Value::Null),
        }
    }
    Ok(at)
}

/// The value at a dotted path, or null: also where a name is two items.
pub fn value_at<'a>(whole: &'a Value, path: &str) -> &'a Value {
    find(whole, path).unwrap_or(&Value::Null)
}

/// Why a name that is two or more items of the list at `shown` is refused.
fn twice(shown: &str, part: &str, places: &[usize]) -> String {
    let places: Vec<String> = places.iter().map(|at| format!("{shown}.{at}")).collect();
    format!(
        "{} items of {shown} are `{part}`: name one by its place, {}",
        places.len(),
        places.join(" or ")
    )
}

/// The stage's name, for an item of version 2's list: what follows the last
/// `/` of its `uses`.
pub(crate) fn stage_name(item: &Value) -> Option<&str> {
    let uses = item.get("uses")?.as_str()?;
    Some(uses.rsplit('/').next().unwrap_or(uses))
}

/// Whether a list's item is the one called `name`: a stage by its name or
/// what it uses, so `stages.plan.approve` means the same in either version;
/// a reviewer by its persona; a check by its name.
fn called(item: &Value, name: &str) -> bool {
    stage_name(item) == Some(name)
        || ["uses", "persona", "name"]
            .iter()
            .any(|key| item.get(*key).and_then(Value::as_str) == Some(name))
}

/// Where the item [`called`] `name` is, or every place it is when it is
/// more than one.
fn only_named(items: &[Value], name: &str) -> Result<Option<usize>, Vec<usize>> {
    let places: Vec<usize> = (0..items.len())
        .filter(|at| called(&items[*at], name))
        .collect();
    match places.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some(*one)),
        _ => Err(places),
    }
}

/// One field that differs, by dotted path. Lists are compared whole.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Change {
    pub path: String,
    pub before: Value,
    pub after: Value,
}

/// What changes from `before` to `after`.
pub fn changes(before: Option<&Config>, after: &Config) -> Vec<Change> {
    diff(
        &before.map(Config::to_json).unwrap_or(Value::Null),
        &after.to_json(),
    )
}

/// [`changes`], between two JSON forms.
pub(crate) fn diff(before: &Value, after: &Value) -> Vec<Change> {
    let mut said = Vec::new();
    walk("", before, after, &mut said);
    said
}

fn walk(path: &str, before: &Value, after: &Value, said: &mut Vec<Change>) {
    // A map that is not there yet is an empty one: its fields are each new.
    let empty = Value::Object(Default::default());
    let (before, after) = match (before, after) {
        (Value::Null, Value::Object(_)) => (&empty, after),
        (Value::Object(_), Value::Null) => (before, &empty),
        _ => (before, after),
    };
    if let (Value::Object(old), Value::Object(new)) = (before, after) {
        let mut names: Vec<&String> = old.keys().chain(new.keys()).collect();
        names.sort();
        names.dedup();
        for name in names {
            let deeper = if path.is_empty() {
                name.clone()
            } else {
                format!("{path}.{name}")
            };
            walk(
                &deeper,
                old.get(name).unwrap_or(&Value::Null),
                new.get(name).unwrap_or(&Value::Null),
                said,
            );
        }
        return;
    }
    // The same stages in the same order: a change inside one is named by the
    // stage, so a switch flipped in the list is still one word in the file.
    let names = |items: &[Value]| -> Option<Vec<String>> {
        items
            .iter()
            .map(|item| stage_name(item).map(str::to_owned))
            .collect()
    };
    match (before, after) {
        (Value::Array(old), Value::Array(new)) => {
            if let (Some(was), Some(now)) = (names(old), names(new)) {
                if was == now && !was.is_empty() {
                    for ((name, old), new) in was.iter().zip(old).zip(new) {
                        walk(&format!("{path}.{name}"), old, new, said);
                    }
                    return;
                }
            }
        }
        // A list of stages written for the first time: each of its fields is new.
        (Value::Null, Value::Array(new)) if !new.is_empty() => {
            if let Some(now) = names(new) {
                for (name, new) in now.iter().zip(new) {
                    walk(&format!("{path}.{name}"), &Value::Null, new, said);
                }
                return;
            }
        }
        _ => {}
    }
    if before != after {
        said.push(Change {
            path: path.to_owned(),
            before: before.clone(),
            after: after.clone(),
        });
    }
}

#[cfg(test)]
#[path = "preset_tests.rs"]
mod tests;
