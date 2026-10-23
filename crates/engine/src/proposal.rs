//! A setup or a change of one field, worked out whole before anything is
//! written: the configuration, the text, the files, and what is left to the
//! person's click.
//!
//! Neither switches Devflow on nor moves Decisions to `enforce`. A request
//! for either is held back to what the file already says and comes out as an
//! [`Ask`]; only [`switched`], which the app calls on the person's click,
//! writes it.

use serde::Serialize;
use serde_json::{Map, Value};

use crate::config::{self, Config, Invalid, Mode};
use crate::detect::Detected;
use crate::folder::{self, State};
use crate::playwright;
use crate::preset::{self, Change, Preset};
use crate::setup::{self, Planned, Script};

/// A change only the person's click makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ask {
    Enable,
    Enforce,
}

impl Ask {
    pub fn word(self) -> &'static str {
        match self {
            Ask::Enable => "enable",
            Ask::Enforce => "enforce",
        }
    }

    /// The field it changes, and the value the click writes.
    fn field(self) -> (&'static str, Value) {
        match self {
            Ask::Enable => ("enabled", Value::Bool(true)),
            Ask::Enforce => ("decisions.mode", Value::from(Mode::Enforce.word())),
        }
    }
}

impl Serialize for Ask {
    fn serialize<S: serde::Serializer>(&self, to: S) -> Result<S::Ok, S::Error> {
        to.serialize_str(self.word())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Proposal {
    pub config: Config,
    pub yaml: String,
    /// Whether the text was laid out again rather than edited in place.
    pub laid_out: bool,
    pub changes: Vec<Change>,
    pub scripts: Vec<Script>,
    pub files: Vec<Planned>,
    pub asks: Vec<Ask>,
}

impl Proposal {
    /// The fields set apart from `shown` when this writes other files than
    /// it would: a yes to `shown` is not a yes to this.
    pub fn changed_since(&self, shown: &Proposal) -> Option<Vec<String>> {
        (self.files != shown.files).then(|| {
            preset::diff(&shown.config.to_json(), &self.config.to_json())
                .into_iter()
                .map(|change| change.path)
                .collect()
        })
    }
}

/// The setup `preset` makes over what `state` is, with `set` folded in as
/// dotted paths.
pub fn setup(
    state: &State,
    preset: Preset,
    set: &Map<String, Value>,
    detected: &Detected,
) -> Result<Proposal, Invalid> {
    let before = said(state);
    let mut wanted = preset::starting(preset, detected).to_json();
    // A setup run again leaves the person's switches where they put them.
    for ask in [Ask::Enable, Ask::Enforce] {
        let (path, _) = ask.field();
        let now = preset::value_at(&before, path);
        if !now.is_null() {
            wanted = preset::set_path(wanted, path, now)?;
        }
    }
    for (path, value) in set {
        wanted = preset::set_path(wanted, path, value)?;
    }
    let asks = held_back(&before, &mut wanted)?;
    let sources: Vec<(String, String)> = [&detected.test, &detected.e2e, &detected.lint]
        .into_iter()
        .flatten()
        .map(|found| (found.command.clone(), found.source.clone()))
        .chain(
            detected
                .e2e_tools
                .iter()
                .filter_map(|tool| Some((tool.run.clone()?, tool.source.clone()))),
        )
        .collect();
    let config = config::from_json(&wanted)?;
    // Before the commands move into scripts: a check the person chose names its tool there.
    let playwright = playwright::wanted(&config, detected)
        .then(|| playwright::text(&config.stages.execution.e2e_dir, playwright::base(detected)));
    let (config, scripts) = setup::scripted(config, &sources);
    let changes = preset::diff(&before, &config.to_json());
    // A setup run again over the person's file keeps their comments, unless
    // what it changes is more than a word.
    let (yaml, laid_out) = folder::rewritten(text_of(state), &changes, &config);
    Ok(Proposal {
        changes,
        files: setup::planned(&yaml, &scripts, playwright.as_deref()),
        config,
        yaml,
        laid_out,
        scripts,
        asks,
    })
}

/// `state`'s file with the field at `path` set to `value`. Works on a file
/// that is invalid but still YAML, which is how one is fixed.
pub fn set(state: &State, path: &str, value: &Value) -> Result<Proposal, Invalid> {
    let text = match state {
        State::Missing => {
            return Err(Invalid::at(
                None,
                path,
                "there is no devflow.yaml yet: set Devflow up first",
            ))
        }
        State::Valid(text, _) | State::Invalid(Some(text), _) => text,
        State::Invalid(None, invalid) => return Err(invalid.clone()),
    };
    let before = said(state);
    if before.is_null() {
        if let State::Invalid(_, invalid) = state {
            return Err(invalid.clone());
        }
    }
    let mut wanted = preset::set_path(before.clone(), path, value)?;
    let asks = held_back(&before, &mut wanted)?;
    written(text, &before, &wanted, asks)
}

/// The person's click: Devflow switched on, or Decisions moved to enforce.
pub fn switched(state: &State, ask: Ask) -> Result<Proposal, Invalid> {
    let State::Valid(text, now) = state else {
        return Err(Invalid::at(
            None,
            "",
            "devflow.yaml is missing or invalid, so nothing can be switched on",
        ));
    };
    let (path, value) = ask.field();
    let before = now.to_json();
    let wanted = preset::set_path(before.clone(), path, &value)?;
    written(text, &before, &wanted, Vec::new())
}

/// The file's text, when there is one that reads as YAML.
fn text_of(state: &State) -> Option<&str> {
    match state {
        State::Valid(text, _) | State::Invalid(Some(text), _) => Some(text),
        _ => None,
    }
}

/// What the file says as JSON: the configuration when it is valid, the raw
/// fields when it is YAML but invalid, and null otherwise.
fn said(state: &State) -> Value {
    match state {
        State::Valid(_, config) => config.to_json(),
        State::Invalid(Some(text), _) => folder::as_json(text).unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

fn written(
    text: &str,
    before: &Value,
    wanted: &Value,
    asks: Vec<Ask>,
) -> Result<Proposal, Invalid> {
    let config = config::from_json(wanted)?;
    // A check the change adds runs a script of its own, as a setup's does.
    let (config, scripts) = match config::from_json(before) {
        Ok(had) => {
            let had: Vec<String> = had
                .stages
                .execution
                .checks
                .into_iter()
                .map(|check| check.name)
                .collect();
            setup::scripted_new(config, &had)
        }
        Err(_) => (config, Vec::new()),
    };
    let changes = if scripts.is_empty() {
        preset::diff(before, wanted)
    } else {
        preset::diff(before, &config.to_json())
    };
    let (yaml, laid_out) = folder::rewritten(Some(text), &changes, &config);
    Ok(Proposal {
        files: setup::config_only(&yaml, &scripts),
        config,
        yaml,
        laid_out,
        changes,
        scripts,
        asks,
    })
}

/// Puts back what only a click may raise, and says what was asked for.
fn held_back(before: &Value, wanted: &mut Value) -> Result<Vec<Ask>, Invalid> {
    let mut asks = Vec::new();
    for ask in [Ask::Enable, Ask::Enforce] {
        let (path, raised) = ask.field();
        let now = preset::value_at(before, path).clone();
        if *preset::value_at(wanted, path) == raised && now != raised {
            let back = if now.is_null() {
                match ask {
                    Ask::Enable => Value::Bool(false),
                    Ask::Enforce => Value::from(Mode::Shadow.word()),
                }
            } else {
                now
            };
            *wanted = preset::set_path(wanted.clone(), path, &back)?;
            asks.push(ask);
        }
    }
    Ok(asks)
}

#[cfg(test)]
#[path = "proposal_tests.rs"]
mod tests;
