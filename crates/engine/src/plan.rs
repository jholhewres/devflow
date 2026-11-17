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
    published_in(&crate::Dialect::DEVFLOW, config)
}

/// [`published`], in `dialect`'s words.
pub fn published_in(dialect: &crate::Dialect, config: &crate::Config) -> Result<(), String> {
    use crate::config::Publish;
    match config.publish() {
        Publish::Board => Ok(()),
        other => Err(format!(
            "publish: {} is not yet — it needs O-08, the {} integration. Set stages.plan.publish to board, and the plan's {}",
            other.word(),
            match other {
                Publish::Jira => "Jira",
                Publish::Linear => "Linear",
                _ => "GitHub Issues",
            },
            dialect.plan_board
        )),
    }
}

/// One card of a plan, as the plan skill fills it. A host that builds one
/// field by field ends with `..Default::default()`: fields are added in 0.2.x.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// How the card's boundary could be abused, each a criterion its tests
    /// prove the abuse refused: rendered among the criteria.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub abuse: Vec<String>,
    /// The plan says the card crosses a trust boundary, whatever its files.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub boundary: bool,
}

/// What an abuse case's checkbox starts with, so a reader tells it apart.
pub const ABUSE: &str = "Abuse case: ";

/// The slices an agent or the board passed, trimmed and checked.
pub fn read(cards: &Value) -> Result<Vec<Slice>, String> {
    read_in(&crate::Dialect::DEVFLOW, cards)
}

/// [`read`], refused in `dialect`'s words.
pub fn read_in(dialect: &crate::Dialect, cards: &Value) -> Result<Vec<Slice>, String> {
    let slices: Vec<Slice> = serde_json::from_value(cards.clone()).map_err(|why| {
        format!(
            "`{}` is a list of {{ key, title, build, criteria, files, verify, depends_on }}: {why}",
            dialect.items
        )
    })?;
    let slices: Vec<Slice> = slices.into_iter().map(trimmed).collect();
    checked_in(dialect, &slices)?;
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
        // A case handed back from a card's body keeps no second prefix.
        abuse: lines(slice.abuse)
            .into_iter()
            .map(|case| case.strip_prefix(ABUSE).map_or(case.clone(), str::to_owned))
            .collect(),
        boundary: slice.boundary,
    }
}

/// Why a plan cannot become cards, or nothing.
pub fn checked(slices: &[Slice]) -> Result<(), String> {
    checked_in(&crate::Dialect::DEVFLOW, slices)
}

/// [`checked`], refused in `dialect`'s words.
pub fn checked_in(dialect: &crate::Dialect, slices: &[Slice]) -> Result<(), String> {
    if slices.is_empty() || slices.len() > MOST_CARDS {
        return Err(format!("a plan has 1 to {MOST_CARDS} {}", dialect.items));
    }
    for (at, slice) in slices.iter().enumerate() {
        let named = format!("{} {} ({})", dialect.item, at + 1, slice.key);
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
        let lines = [
            &slice.criteria,
            &slice.files,
            &slice.depends_on,
            &slice.abuse,
        ];
        if slice.build.chars().count() > LONGEST_BUILD
            || slice.verify.chars().count() > LONGEST_LINE
            || lines.iter().any(|all| all.len() > MOST_ITEMS)
            || lines
                .iter()
                .any(|all| all.iter().any(|one| one.chars().count() > LONGEST_LINE))
        {
            return Err(format!(
                "{named}: too long — a build of {LONGEST_BUILD} characters, at most {MOST_ITEMS} criteria, abuse cases, files and depends_on, each line {LONGEST_LINE}"
            ));
        }
        for key in &slice.depends_on {
            if key == &slice.key || (!is_key(slices, key) && !names_a_card(key)) {
                return Err(format!(
                    "{named}: depends_on `{key}` {}",
                    dialect.plan_outside
                ));
            }
        }
    }
    if ordered(slices).is_none() {
        return Err(format!(
            "the {}' depends_on go round in a circle, so none of them could start",
            dialect.items
        ));
    }
    Ok(())
}

fn is_key(slices: &[Slice], key: &str) -> bool {
    slices.iter().any(|one| one.key == key)
}

/// Whether a `depends_on` that is no key of the plan names a card already on
/// the board, by its id or its `#42`: how a plan waits on another epic.
pub fn names_a_card(on: &str) -> bool {
    let number = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    on.starts_with("card_")
        || number(on)
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

/// Whether a card crosses a trust boundary: the plan says so, or one of
/// its files matches a `sensitive` glob (`review.scale.sensitive`, else
/// [`crate::scale::SENSITIVE`]). Never read from the criteria's words,
/// which are in whatever language the person writes.
pub fn crosses_a_boundary(slice: &Slice, sensitive: &[String]) -> Option<String> {
    if slice.boundary {
        return Some("the plan marks it a boundary".to_owned());
    }
    slice.files.iter().find_map(|file| {
        let file = file.trim_matches('`');
        sensitive
            .iter()
            .find(|pattern| crate::scale::matches(pattern, file))
            .map(|pattern| format!("{file} is a sensitive path ({pattern})"))
    })
}

/// The boundary cards that name no abuse case, each by its key and why it
/// is a boundary: a warning on the plan, never a refusal.
pub fn unguarded(slices: &[Slice], sensitive: &[String]) -> Vec<(String, String)> {
    slices
        .iter()
        .filter(|slice| slice.abuse.is_empty())
        .filter_map(|slice| {
            crosses_a_boundary(slice, sensitive).map(|why| (slice.key.clone(), why))
        })
        .collect()
}

/// [`unguarded`] as a plan's answer says it: each with what to add.
pub fn unguarded_said(unguarded: &[(String, String)]) -> Vec<String> {
    unguarded
        .iter()
        .map(|(key, why)| {
            format!(
                "{key}: {why}, and it names no abuse case: add `abuse`, how its boundary could be abused, each proven refused by a test"
            )
        })
        .collect()
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
    if !slice.criteria.is_empty() || !slice.abuse.is_empty() {
        let _ = writeln!(body, "## {}", criteria::HEADING);
        for criterion in &slice.criteria {
            let _ = writeln!(body, "- [ ] {criterion}");
        }
        for case in &slice.abuse {
            let _ = writeln!(body, "- [ ] {ABUSE}{case}");
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
