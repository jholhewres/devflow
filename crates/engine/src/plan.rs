//! Devflow's plan: an epic's work as cards on the board, each with what to
//! build, its criteria as checkboxes, the files it likely touches, the
//! command that verifies it and the cards it waits on.
//!
//! The board is the plan, so nothing here is kept beside the cards: a slice
//! becomes a card's title and body, and its `depends_on` the board's edges.

use std::fmt::Write as _;

use crate::criteria;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Every card Devflow makes says so in its title, and every comment it writes.
pub const PREFIX: &str = "[devflow] ";

/// More than this is not one epic's plan.
pub const MOST_CARDS: usize = 30;
const LONGEST_KEY: usize = 40;
const LONGEST_TITLE: usize = 200;
const LONGEST_BUILD: usize = 4000;
const LONGEST_LINE: usize = 500;
const MOST_ITEMS: usize = 12;

/// Where the plan's cards go, or why they cannot go there yet. Only the
/// board takes them: the trackers wait on their own integration.
pub fn published(config: &crate::Config) -> Result<(), String> {
    use crate::config::Publish;
    match config.publish() {
        Publish::Board => Ok(()),
        other => Err(format!(
            "publish: {} is not yet — it needs O-08, the {} integration. Set stages.plan.publish to board, and the plan's slices are made as work items in .devflow/work/.",
            other.word(),
            match other {
                Publish::Jira => "Jira",
                Publish::Linear => "Linear",
                _ => "GitHub Issues",
            }
        )),
    }
}

/// One card of a plan, as the plan skill fills it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Slice {
    /// A short local id that `depends_on` refers to.
    pub key: String,
    /// The behaviour, without the prefix the card's title gets.
    pub title: String,
    #[serde(default)]
    pub build: String,
    #[serde(default)]
    pub criteria: Vec<String>,
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default)]
    pub verify: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
}

/// The slices an agent or the board passed, trimmed and checked.
pub fn read(cards: &Value) -> Result<Vec<Slice>, String> {
    let slices: Vec<Slice> = serde_json::from_value(cards.clone()).map_err(|why| {
        format!("`cards` is a list of {{ key, title, build, criteria, files, verify, depends_on }}: {why}")
    })?;
    let slices: Vec<Slice> = slices.into_iter().map(trimmed).collect();
    checked(&slices)?;
    Ok(slices)
}

fn trimmed(slice: Slice) -> Slice {
    let lines = |all: Vec<String>| -> Vec<String> {
        all.iter()
            .map(|one| one.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter(|one| !one.is_empty())
            .collect()
    };
    let title = slice.title.split_whitespace().collect::<Vec<_>>().join(" ");
    Slice {
        key: slice.key.trim().to_owned(),
        title: title
            .strip_prefix(PREFIX.trim_end())
            .unwrap_or(&title)
            .trim()
            .to_owned(),
        build: slice.build.trim().to_owned(),
        criteria: lines(slice.criteria),
        files: lines(slice.files),
        verify: slice.verify.trim().to_owned(),
        depends_on: lines(slice.depends_on),
    }
}

/// Why a plan cannot become cards, or nothing.
pub fn checked(slices: &[Slice]) -> Result<(), String> {
    if slices.is_empty() || slices.len() > MOST_CARDS {
        return Err(format!("a plan has 1 to {MOST_CARDS} cards"));
    }
    for (at, slice) in slices.iter().enumerate() {
        let named = format!("card {} ({})", at + 1, slice.key);
        if slice.key.is_empty() || slice.key.len() > LONGEST_KEY {
            return Err(format!("{named}: a key of 1 to {LONGEST_KEY} characters"));
        }
        if slices[..at].iter().any(|one| one.key == slice.key) {
            return Err(format!("{named}: the key is used twice"));
        }
        if slice.title.is_empty() || slice.title.chars().count() > LONGEST_TITLE {
            return Err(format!(
                "{named}: a title of 1 to {LONGEST_TITLE} characters"
            ));
        }
        let lines = [&slice.criteria, &slice.files, &slice.depends_on];
        if slice.build.chars().count() > LONGEST_BUILD
            || slice.verify.chars().count() > LONGEST_LINE
            || lines.iter().any(|all| all.len() > MOST_ITEMS)
            || lines
                .iter()
                .any(|all| all.iter().any(|one| one.chars().count() > LONGEST_LINE))
        {
            return Err(format!(
                "{named}: too long — a build of {LONGEST_BUILD} characters, at most {MOST_ITEMS} criteria, files and depends_on, each line {LONGEST_LINE}"
            ));
        }
        for key in &slice.depends_on {
            if key == &slice.key || (!is_key(slices, key) && !names_a_card(key)) {
                return Err(format!(
                    "{named}: depends_on `{key}` is not another card of this plan, nor a card \
                     on the board (`card_…` or `#42`)"
                ));
            }
        }
    }
    if ordered(slices).is_none() {
        return Err(
            "the cards' depends_on go round in a circle, so none of them could start".to_owned(),
        );
    }
    Ok(())
}

fn is_key(slices: &[Slice], key: &str) -> bool {
    slices.iter().any(|one| one.key == key)
}

/// Whether a `depends_on` that is no key of the plan names a card already on
/// the board, by its id or its `#42`: how a plan waits on another epic.
pub fn names_a_card(on: &str) -> bool {
    on.starts_with("card_")
        || on
            .strip_prefix('#')
            .is_some_and(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
}

/// What `slice` waits on outside the plan: cards already on the board.
pub fn outside<'a>(slices: &[Slice], slice: &'a Slice) -> Vec<&'a str> {
    slice
        .depends_on
        .iter()
        .filter(|on| !is_key(slices, on))
        .map(String::as_str)
        .collect()
}

/// The cards each one waits on, as indexes into the plan.
pub fn waits_on(slices: &[Slice]) -> Vec<Vec<usize>> {
    slices
        .iter()
        .map(|slice| {
            slice
                .depends_on
                .iter()
                .filter_map(|key| slices.iter().position(|one| &one.key == key))
                .collect()
        })
        .collect()
}

/// An order in which every card comes after the ones it waits on, or `None`
/// for a circle.
fn ordered(slices: &[Slice]) -> Option<Vec<usize>> {
    let waits = waits_on(slices);
    let mut done: Vec<usize> = Vec::with_capacity(slices.len());
    while done.len() < slices.len() {
        let next = (0..slices.len())
            .find(|at| !done.contains(at) && waits[*at].iter().all(|on| done.contains(on)))?;
        done.push(next);
    }
    Some(done)
}

/// The card's title.
pub fn title(slice: &Slice) -> String {
    format!("{PREFIX}{}", slice.title)
}

/// The card's body: readable as it stands wherever the text goes, with the
/// criteria where `crate::criteria` reads them.
pub fn body(slice: &Slice) -> String {
    let mut body = String::new();
    if !slice.build.is_empty() {
        let _ = write!(body, "{}\n\n", slice.build);
    }
    if !slice.criteria.is_empty() {
        let _ = writeln!(body, "## {}", criteria::HEADING);
        for criterion in &slice.criteria {
            let _ = writeln!(body, "- [ ] {criterion}");
        }
        body.push('\n');
    }
    if !slice.files.is_empty() {
        body.push_str("## Likely files\n");
        for file in &slice.files {
            let _ = if file.contains('`') {
                writeln!(body, "- {file}")
            } else {
                writeln!(body, "- `{file}`")
            };
        }
        body.push('\n');
    }
    if !slice.verify.is_empty() {
        let _ = write!(body, "## Verify\n```sh\n{}\n```\n", slice.verify);
    }
    body.trim_end().to_owned()
}

#[cfg(test)]
#[path = "plan_tests.rs"]
mod tests;
