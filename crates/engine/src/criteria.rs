//! A card's acceptance criteria: the checkboxes of a `## Acceptance criteria`
//! list in its body.
//!
//! In the body rather than in a table, so the card reads the same wherever
//! its text goes — the board, an agent's `devpit_card`, a paste — and a tick
//! is an edit of that text, which nothing else can disagree with.

/// The heading the criteria live under.
pub const HEADING: &str = "Acceptance criteria";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Criterion {
    pub text: String,
    pub done: bool,
}

/// The criteria a body holds, in order.
pub fn criteria(body: &str) -> Vec<Criterion> {
    boxes(body)
        .into_iter()
        .map(|found| found.criterion)
        .collect()
}

/// The body with its `at`-th criterion ticked, or unticked; `None` when it
/// has no such criterion.
pub fn ticked(body: &str, at: usize, done: bool) -> Option<String> {
    let found = boxes(body).into_iter().nth(at)?;
    let mut lines: Vec<String> = body.split('\n').map(str::to_owned).collect();
    let line = lines.get_mut(found.line)?;
    line.replace_range(found.mark..found.mark + 1, if done { "x" } else { " " });
    Some(lines.join("\n"))
}

/// A checkbox under the heading: its line, the byte of its mark in that line,
/// and what it says.
struct Found {
    line: usize,
    mark: usize,
    criterion: Criterion,
}

fn boxes(body: &str) -> Vec<Found> {
    let mut under: Option<usize> = None;
    let mut fenced = false;
    let mut found = Vec::new();
    for (line, text) in body.split('\n').enumerate() {
        let text = text.trim_end_matches('\r');
        // A fence's lines are code, whatever they look like.
        if text.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        if let Some((level, title)) = heading(text) {
            under = match under {
                // A subheading stays inside the list's section.
                Some(at) if level > at => Some(at),
                _ => is_heading(title).then_some(level),
            };
            continue;
        }
        if under.is_none() {
            continue;
        }
        if let Some((mark, criterion)) = checkbox(text) {
            found.push(Found {
                line,
                mark,
                criterion,
            });
        }
    }
    found
}

fn is_heading(title: &str) -> bool {
    title
        .trim_end_matches(':')
        .trim()
        .eq_ignore_ascii_case(HEADING)
}

fn heading(line: &str) -> Option<(usize, &str)> {
    let level = line.bytes().take_while(|byte| *byte == b'#').count();
    let rest = &line[level..];
    ((1..=6).contains(&level) && rest.starts_with([' ', '\t']))
        .then(|| (level, rest.trim().trim_end_matches('#').trim()))
}

/// `- [ ] text` or `- [x] text`, with `*` or `+` for `-` and any indent.
fn checkbox(line: &str) -> Option<(usize, Criterion)> {
    let indent = line.len() - line.trim_start().len();
    let rest = line[indent..].strip_prefix(['-', '*', '+'])?;
    let gap = rest.len() - rest.trim_start().len();
    if gap == 0 {
        return None;
    }
    let mark = indent + 1 + gap + 1;
    let after = rest.trim_start();
    let done = match after.get(..3)? {
        "[ ]" => false,
        "[x]" | "[X]" => true,
        _ => return None,
    };
    let text = after[3..].trim();
    (!text.is_empty()).then(|| {
        (
            mark,
            Criterion {
                text: text.to_owned(),
                done,
            },
        )
    })
}

#[cfg(test)]
#[path = "criteria_tests.rs"]
mod tests;
