//! Devflow's brief: the epic card that says what the work is for — its goal,
//! who it is for, how success is checked, what is out of scope — and, once
//! the context stage ran, what the project already knows about it.
//!
//! Written into the card's body as Markdown a person can read and edit. A
//! later write changes only what it was given: the other fields, and
//! anything else in the body, stay as they were.

use serde::Deserialize;

use crate::plan::PREFIX;

/// What an epic's title starts with.
pub fn epic_title(title: &str) -> String {
    let title = title.split_whitespace().collect::<Vec<_>>().join(" ");
    let bare = title
        .strip_prefix(PREFIX.trim_end())
        .unwrap_or(&title)
        .trim();
    let bare = bare.strip_prefix("Brief:").unwrap_or(bare).trim();
    format!("{PREFIX}Brief: {bare}")
}

/// What `devpit_devflow_brief` is given. Every field is optional: the
/// context stage passes only `context`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Brief {
    pub title: Option<String>,
    pub goal: Option<String>,
    pub for_whom: Option<String>,
    pub success: Option<String>,
    pub out_of_scope: Option<Vec<String>>,
    pub constraints: Option<Vec<String>>,
    pub decisions: Option<Vec<String>>,
    /// The context stage's summary, the epic's `## Context` section.
    pub context: Option<String>,
}

/// The longest a brief may be, all of it: a card body is read whole.
pub const LONGEST: usize = 64 * 1024;

const BRIEF: &str = "Brief";
const CONTEXT: &str = "Context";
const LINES: [(&str, Field); 3] = [
    ("Goal", Field::Goal),
    ("For whom", Field::ForWhom),
    ("Success", Field::Success),
];
const LISTS: [(&str, Field); 3] = [
    ("Out of scope", Field::OutOfScope),
    ("Constraints", Field::Constraints),
    ("Decisions", Field::Decisions),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Goal,
    ForWhom,
    Success,
    OutOfScope,
    Constraints,
    Decisions,
}

impl Brief {
    /// Whether it says anything of the brief itself, beyond the context.
    pub fn has_fields(&self) -> bool {
        self.goal.is_some()
            || self.for_whom.is_some()
            || self.success.is_some()
            || self.out_of_scope.is_some()
            || self.constraints.is_some()
            || self.decisions.is_some()
    }

    fn line(&self, field: Field) -> Option<&String> {
        match field {
            Field::Goal => self.goal.as_ref(),
            Field::ForWhom => self.for_whom.as_ref(),
            _ => self.success.as_ref(),
        }
    }

    fn list(&self, field: Field) -> Option<&Vec<String>> {
        match field {
            Field::OutOfScope => self.out_of_scope.as_ref(),
            Field::Constraints => self.constraints.as_ref(),
            _ => self.decisions.as_ref(),
        }
    }

    /// This brief over `under`: each field it has replaces the other's.
    fn over(&self, under: Brief) -> Brief {
        Brief {
            title: None,
            goal: self.goal.clone().or(under.goal),
            for_whom: self.for_whom.clone().or(under.for_whom),
            success: self.success.clone().or(under.success),
            out_of_scope: self.out_of_scope.clone().or(under.out_of_scope),
            constraints: self.constraints.clone().or(under.constraints),
            decisions: self.decisions.clone().or(under.decisions),
            context: None,
        }
    }
}

/// The body with the brief written into it.
pub fn written(body: &str, brief: &Brief) -> String {
    let mut parts = sections(body);
    let brief_at = parts
        .iter()
        .position(|(title, _)| title.as_deref() == Some(BRIEF));
    if brief.has_fields() {
        let old = brief_at.map(|at| parsed(&parts[at].1)).unwrap_or_default();
        let text = rendered(&brief.over(old));
        match brief_at {
            Some(at) => parts[at].1 = text,
            // After the text that was there, which is the request: under the
            // brief's heading it would be read as part of the brief.
            None => parts.insert(1, (Some(BRIEF.to_owned()), text)),
        }
    }
    if let Some(context) = brief.context.as_deref().map(str::trim) {
        let text = match context.strip_prefix("## Context") {
            Some(_) => context.to_owned(),
            None => format!("## {CONTEXT}\n{context}"),
        };
        let brief_at = parts
            .iter()
            .position(|(title, _)| title.as_deref() == Some(BRIEF));
        match parts
            .iter()
            .position(|(title, _)| title.as_deref() == Some(CONTEXT))
        {
            Some(at) => parts[at].1 = text,
            None => parts.insert(
                brief_at.map_or(parts.len(), |at| at + 1),
                (Some(CONTEXT.to_owned()), text),
            ),
        }
    }
    parts
        .iter()
        .map(|(_, text)| text.trim())
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// The brief an epic's body says, when it has a `## Brief` section.
pub fn read(body: &str) -> Option<Brief> {
    sections(body)
        .into_iter()
        .find(|(title, _)| title.as_deref() == Some(BRIEF))
        .map(|(_, text)| parsed(&text))
}

/// The body cut at its `#` and `##` headings, outside code fences: each
/// part with its heading's title, the text before the first one with none.
fn sections(body: &str) -> Vec<(Option<String>, String)> {
    let mut parts: Vec<(Option<String>, String)> = vec![(None, String::new())];
    let mut fenced = false;
    for line in body.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
        }
        let top = ["# ", "## "]
            .iter()
            .find_map(|mark| line.strip_prefix(mark))
            .filter(|_| !fenced);
        if let Some(title) = top {
            parts.push((Some(title.trim().to_owned()), String::new()));
        }
        if let Some((_, text)) = parts.last_mut() {
            text.push_str(line);
            text.push('\n');
        }
    }
    parts
}

/// The brief a `## Brief` section says, as `rendered` writes it.
fn parsed(text: &str) -> Brief {
    let mut brief = Brief::default();
    let mut list: Option<Field> = None;
    for line in text.lines() {
        if let Some(title) = line.strip_prefix("### ") {
            list = LISTS
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(title.trim()))
                .map(|(_, field)| *field);
            continue;
        }
        let Some(item) = line.strip_prefix("- ") else {
            continue;
        };
        if let Some(field) = list {
            let all = match field {
                Field::OutOfScope => &mut brief.out_of_scope,
                Field::Constraints => &mut brief.constraints,
                _ => &mut brief.decisions,
            };
            all.get_or_insert_with(Vec::new)
                .push(item.trim().to_owned());
            continue;
        }
        for (name, field) in LINES {
            let Some(said) = item
                .strip_prefix(name)
                .and_then(|rest| rest.strip_prefix(':'))
            else {
                continue;
            };
            let slot = match field {
                Field::Goal => &mut brief.goal,
                Field::ForWhom => &mut brief.for_whom,
                _ => &mut brief.success,
            };
            *slot = Some(said.trim().to_owned());
        }
    }
    brief
}

fn rendered(brief: &Brief) -> String {
    let mut text = format!("## {BRIEF}\n");
    for (name, field) in LINES {
        if let Some(said) = brief.line(field) {
            text.push_str(&format!("- {name}: {}\n", one_line(said)));
        }
    }
    for (name, field) in LISTS {
        let Some(all) = brief.list(field) else {
            continue;
        };
        text.push_str(&format!("\n### {name}\n"));
        let items: Vec<String> = all
            .iter()
            .map(|one| one_line(one))
            .filter(|one| !one.is_empty())
            .collect();
        if items.is_empty() {
            text.push_str("- none\n");
        }
        for item in items {
            text.push_str(&format!("- {item}\n"));
        }
    }
    text
}

fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
#[path = "brief_tests.rs"]
mod tests;
