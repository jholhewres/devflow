//! A review asked on demand, without a card: of a pull request, of a range
//! between two commits, or of a worktree of the project. What it is asked,
//! the name its runs are kept under in devpit's folder for the project, and
//! the criteria it is held to in place of a card's.

use serde_json::{Map, Value};

use crate::review::{self, FIELDS};

/// The most criteria a review without a card is given, and the most of each.
const MOST_CRITERIA: usize = 30;
const MOST_CRITERION: usize = 500;
/// How much of a pull request's body stands in for its criteria.
const MOST_BODY: usize = 2_000;

/// What is reviewed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    /// A pull request of the project's GitHub repository, by number.
    Pr(u64),
    /// From `base` to `head`, both branches or commits.
    Range { base: String, head: String },
    /// A worktree of the project, its HEAD against `base` or the default branch.
    Path { path: String, base: Option<String> },
}

impl Subject {
    /// How the session names it again when it hands its reports back.
    pub fn again(&self) -> String {
        match self {
            Subject::Pr(number) => format!("pr {number}"),
            Subject::Range { base, head } => format!("base \"{base}\" and head \"{head}\""),
            Subject::Path { path, base: None } => format!("path \"{path}\""),
            Subject::Path {
                path,
                base: Some(base),
            } => format!("path \"{path}\" and base \"{base}\""),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Standalone {
    pub subject: Subject,
    pub criteria: Vec<String>,
    pub run: Option<String>,
    pub reports: Vec<Value>,
    /// A range already merged and in production, followed up, never held.
    pub retro: bool,
}

/// The review's input when it names no card; `None` when it does, which is
/// [`review::asked`]'s to read.
pub fn standalone(params: &Value) -> Result<Option<Standalone>, String> {
    let fields = params
        .as_object()
        .ok_or("the review takes a card, a pr, a base and a head, or a path")?;
    if fields.get("card").is_some_and(|card| !card.is_null()) {
        return Ok(None);
    }
    if let Some(extra) = fields
        .keys()
        .find(|key| !FIELDS.contains(&key.as_str()) && key.as_str() != "project")
    {
        return Err(format!("`{extra}` is not a field of the review"));
    }
    if fields.contains_key("previous") {
        return Err("`previous` re-reviews a card's run: pass the card".to_owned());
    }
    let word = |key: &str| text(fields, key);
    let revision = |key: &str| -> Result<Option<String>, String> {
        match word(key) {
            Some(said) if !crate::git::plain_revision(&said) => {
                Err(format!("`{key}` is a branch or a commit"))
            }
            said => Ok(said),
        }
    };
    let (base, head, path) = (revision("base")?, revision("head")?, word("path"));
    let subject = match (fields.get("pr"), base, head, path) {
        (Some(pr), None, None, None) => {
            Subject::Pr(pr_number(pr).ok_or("`pr` is a pull request's number or its URL")?)
        }
        (Some(_), ..) => return Err("`pr` is reviewed alone: leave out `base`, `head` and `path`".to_owned()),
        (None, Some(base), Some(head), None) => Subject::Range { base, head },
        (None, base, None, Some(path)) => Subject::Path { path, base },
        (None, _, Some(_), Some(_)) => {
            return Err("a worktree is reviewed at its own HEAD: leave out `head`".to_owned())
        }
        (None, ..) => return Err(
            "which change? pass `card`, or `pr`, or `base` and `head`, or `path` (a worktree of the project)"
                .to_owned(),
        ),
    };
    let retro = match word("mode").as_deref() {
        None => false,
        Some("retro") if matches!(subject, Subject::Range { .. }) => true,
        Some("retro") => {
            return Err(
                "a retro review reads what is already merged: pass `base` and `head`".to_owned(),
            )
        }
        Some(_) => return Err("`mode` is retro, or left out".to_owned()),
    };
    let reports = review::reports_of(fields)?;
    let run = word("run");
    review::handed_back(run.as_deref(), &reports)?;
    Ok(Some(Standalone {
        subject,
        criteria: criteria_of(fields.get("criteria"))?,
        run,
        reports,
        retro,
    }))
}

fn text(fields: &Map<String, Value>, key: &str) -> Option<String> {
    fields
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|said| !said.is_empty())
        .map(str::to_owned)
}

fn criteria_of(said: Option<&Value>) -> Result<Vec<String>, String> {
    let list = match said {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(list)) if list.len() <= MOST_CRITERIA => list,
        _ => {
            return Err(format!(
                "`criteria` is a list of at most {MOST_CRITERIA} lines"
            ))
        }
    };
    list.iter()
        .map(|one| {
            one.as_str()
                .map(one_line)
                .filter(|line| !line.is_empty() && line.len() <= MOST_CRITERION)
                .ok_or_else(|| {
                    format!("each criterion is one line of text, at most {MOST_CRITERION} bytes")
                })
        })
        .collect()
}

/// Text on one line: a checkbox it becomes cannot be broken out of.
fn one_line(said: &str) -> String {
    said.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A pull request's number: as a number, `#42`, or a URL ending `/pull/42`.
pub fn pr_number(said: &Value) -> Option<u64> {
    let number = match said {
        Value::Number(number) => number.as_u64()?,
        Value::String(said) => {
            let said = said.trim().trim_end_matches('/');
            let last = match said.rsplit_once("/pull/") {
                Some((_, last)) => last,
                None => said.strip_prefix('#').unwrap_or(said),
            };
            last.parse().ok()?
        }
        _ => return None,
    };
    (number > 0).then_some(number)
}

/// The folder a review's runs are kept in: the pull request's, or the
/// range's by the commits it read.
pub fn label(subject: &Subject, base: &str, head: &str) -> String {
    let short = |sha: &str| sha.chars().take(12).collect::<String>();
    match subject {
        Subject::Pr(number) => format!("pr-{number}"),
        _ => format!("{}-{}", short(base), short(head)),
    }
}

/// The pull request a review's folder is of, when it is one's.
pub fn pr_of(label: &str) -> Option<u64> {
    label
        .strip_prefix("pr-")?
        .parse()
        .ok()
        .filter(|number| *number > 0)
}

/// What a pull request is held to: the criteria passed, then its body's
/// checkboxes; with neither, its title and body.
pub fn pr_criteria(given: &[String], title: &str, body: &str) -> Vec<String> {
    let mut criteria: Vec<String> = given.to_vec();
    criteria.extend(
        crate::criteria::criteria(body)
            .into_iter()
            .map(|one| one_line(&one.text)),
    );
    if criteria.is_empty() {
        let body: String = one_line(body).chars().take(MOST_BODY).collect();
        criteria.extend(
            [one_line(title), body]
                .into_iter()
                .filter(|line| !line.is_empty()),
        );
    }
    criteria.truncate(MOST_CRITERIA);
    criteria
}

/// A card's body holding `criteria`, which the review reads them from.
pub fn body_of(criteria: &[String]) -> String {
    let mut body = format!("## {}\n", crate::criteria::HEADING);
    for criterion in criteria {
        body.push_str(&format!("- [ ] {criterion}\n"));
    }
    body
}

/// What the session does next, said for a review without a card. `detached`
/// is the HEAD read in a worktree of devpit's, gone once the review is.
pub fn next(
    subject: &Subject,
    label: &str,
    stamp: &str,
    pending: &[String],
    detached: Option<&str>,
    retro: bool,
) -> String {
    if pending.is_empty() {
        let posted = match subject {
            Subject::Pr(number) => format!(
                "drafts it for pull request #{number}, and posts it there only after the person's explicit yes to that draft"
            ),
            _ if retro => "drafts one follow-up ticket per medium or worse finding, to file".to_owned(),
            _ => "drafts it to paste where the person wants it".to_owned(),
        };
        let impact = if retro {
            " The code is in production: for each defect, run its `impact` read-only (the data or logs it touched since the deploy, never a write) and tell the person what it showed."
        } else {
            ""
        };
        return format!(
            "Done: the findings are in findings.json; nothing is commented on any card.{impact} devpit_devflow_publish with review \"{label}/{stamp}\" {posted}."
        );
    }
    let reading = detached.map_or_else(String::new, |head| {
        format!(" A file as HEAD has it is read with `git show {head}:<path>`, never by checking HEAD out.")
    });
    let impact = if retro {
        " The range is in production: give each medium or worse defect an `impact`, the read-only query or log search for what it touched since the deploy."
    } else {
        ""
    };
    format!(
        "Review {} yourself: one fresh subagent per persona, each given only the packet and its persona beside it, each answering one findings object.{reading}{impact} Then call devpit_devflow_review again with {}, run \"{stamp}\" and reports: those objects.",
        pending.join(", "),
        subject.again()
    )
}

#[cfg(test)]
#[path = "adhoc_tests.rs"]
mod tests;
