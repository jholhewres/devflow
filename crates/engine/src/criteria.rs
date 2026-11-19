//! A card's acceptance criteria: the checkboxes of a `## Acceptance criteria`
//! list in its body, or under a heading the project names in devflow.yaml's
//! `criteria.headings`.
//!
//! In the body rather than in a table, so the card reads the same wherever
//! its text goes — the board, an agent's `item`, a paste — and a tick
//! is an edit of that text, which nothing else can disagree with.

/// The heading the criteria live under.
pub const HEADING: &str = "Acceptance criteria";
/// The most headings devflow.yaml's `criteria.headings` names.
pub const MOST_HEADINGS: usize = 10;
/// The longest of them, in characters.
pub const LONGEST_HEADING: usize = 80;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Criterion {
    pub text: String,
    pub done: bool,
}

/// The criteria a body holds, in order.
pub fn criteria(body: &str) -> Vec<Criterion> {
    criteria_in(body, &[])
}

/// [`criteria`], also read under each of `headings`, in any case.
pub fn criteria_in(body: &str, headings: &[String]) -> Vec<Criterion> {
    boxes(body, headings)
        .into_iter()
        .map(|found| found.criterion)
        .collect()
}

/// The body with its `at`-th criterion ticked, or unticked; `None` when it
/// has no such criterion.
pub fn ticked(body: &str, at: usize, done: bool) -> Option<String> {
    let found = boxes(body, &[]).into_iter().nth(at)?;
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

/// Checkboxes outside every criteria section, by the nearest heading above
/// them (empty when none is): none of them is read as a criterion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unread {
    pub heading: String,
    pub count: usize,
    /// A criteria heading the body has with no checkbox under it: there,
    /// only empty, so it is not called missing.
    pub empty: Option<String>,
}

/// The checkboxes a body holds that are not criteria, a group per heading
/// they sit under, in the order the headings come.
pub fn unread(body: &str) -> Vec<Unread> {
    unread_in(body, &[])
}

/// [`unread`], with `headings` read as criteria too.
pub fn unread_in(body: &str, headings: &[String]) -> Vec<Unread> {
    let scan = scanned(body, headings);
    let read = scan.found.iter().any(|(_, read)| read.is_some());
    let empty = scan.heading.filter(|_| !read);
    let mut groups: Vec<Unread> = Vec::new();
    for (heading, _) in scan.found.into_iter().filter(|(_, read)| read.is_none()) {
        match groups.iter_mut().find(|group| group.heading == heading) {
            Some(group) => group.count += 1,
            None => groups.push(Unread {
                heading,
                count: 1,
                empty: empty.clone(),
            }),
        }
    }
    groups
}

fn boxes(body: &str, headings: &[String]) -> Vec<Found> {
    scanned(body, headings)
        .found
        .into_iter()
        .filter_map(|(_, read)| read)
        .collect()
}

/// Every checkbox outside code, with the nearest heading above it, and as a
/// criterion when it is under a criteria heading; and the first such heading.
struct Scan {
    found: Vec<(String, Option<Found>)>,
    heading: Option<String>,
}

fn scanned(body: &str, headings: &[String]) -> Scan {
    let mut first: Option<String> = None;
    let mut under: Option<usize> = None;
    let mut nearest = String::new();
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
            nearest = title.to_owned();
            under = match under {
                // A subheading stays inside the list's section.
                Some(at) if level > at => Some(at),
                _ => is_heading(title, headings).then_some(level),
            };
            if under == Some(level) && first.is_none() {
                first = Some(bare(title).to_owned());
            }
            continue;
        }
        if let Some((mark, criterion)) = checkbox(text) {
            let read = under.is_some().then_some(Found {
                line,
                mark,
                criterion,
            });
            found.push((nearest.clone(), read));
        }
    }
    Scan {
        found,
        heading: first,
    }
}

fn is_heading(title: &str, headings: &[String]) -> bool {
    let title = bare(title);
    title.eq_ignore_ascii_case(HEADING)
        || headings
            .iter()
            .any(|one| bare(one).to_lowercase() == title.to_lowercase())
}

fn bare(title: &str) -> &str {
    title.trim_end_matches(':').trim()
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
