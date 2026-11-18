//! devflow.yaml edited as text: a value set, a key added or removed where it
//! stands, so the person's comments and the fields devflow does not read stay
//! wherever the change does not reach.

use serde_json::Value as Json;

use crate::node::{self, Node, Value};
use crate::render::scalar;

/// `text` with the field at the dotted `path` set to `value`, a null value
/// removing it; `None` when the text cannot be edited there in place.
pub(crate) fn set(text: &str, path: &str, value: &Json) -> Option<String> {
    let tree = node::from_yaml(text).ok()?;
    let mut lines: Vec<String> = text.split_inclusive('\n').map(str::to_owned).collect();
    if lines.last().is_some_and(|last| !last.ends_with('\n')) {
        lines.last_mut()?.push('\n');
    }
    let parts: Vec<&str> = path.split('.').collect();
    let edited = edit(lines, &tree, &parts, value, Vec::new())?;
    // New lines end as the file's own do.
    Some(if text.contains("\r\n") {
        edited.replace("\r\n", "\n").replace('\n', "\r\n")
    } else {
        edited
    })
}

/// The edit at `parts` below `map`; `chain` holds the keys walked through,
/// so a map a removal leaves empty goes with its own key.
fn edit(
    lines: Vec<String>,
    map: &Node,
    parts: &[&str],
    value: &Json,
    mut chain: Vec<Entry>,
) -> Option<String> {
    let (part, rest) = parts.split_first()?;
    let here = block_map(map, &lines)?;
    let Value::Map(items) = &map.value else {
        return None;
    };
    let Some((key, child)) = items.iter().find(|(key, _)| key.name == *part) else {
        if value.is_null() {
            return Some(lines.concat());
        }
        return insert(lines, &here, items, part, &nested(rest, value));
    };
    let entry = Entry {
        line: key.line?.checked_sub(1)?,
        col: here.col,
        only: items.len() == 1,
    };
    chain.push(entry);
    if rest.is_empty() {
        return if value.is_null() {
            remove(lines, &chain)
        } else {
            replace(lines, &entry, part, child, value)
        };
    }
    match &child.value {
        Value::Map(_) => edit(lines, child, rest, value, chain),
        // An item of a list, by its place or its stage's name; a whole item
        // set or removed is the list replaced instead.
        Value::Seq(items) => {
            let (name, deeper) = rest.split_first()?;
            let item = item_of(items, name)?;
            if deeper.is_empty() {
                return None;
            }
            edit(lines, item, deeper, value, Vec::new())
        }
        Value::Null if value.is_null() => Some(lines.concat()),
        Value::Null => replace(lines, &entry, part, child, &nested(rest, value)),
        _ => None,
    }
}

/// A map written in block style: the column its keys stand at.
struct Here {
    col: usize,
}

/// A key of a block map: its line (from 0), its column, and whether it is
/// the map's only key.
#[derive(Clone, Copy)]
struct Entry {
    line: usize,
    col: usize,
    only: bool,
}

fn block_map(node: &Node, lines: &[String]) -> Option<Here> {
    let Value::Map(items) = &node.value else {
        return None;
    };
    let (first, _) = items.first()?;
    let (line, col) = (first.line?.checked_sub(1)?, first.col?);
    // Only indentation and a list's dashes stand before a block map's first
    // key; a flow map (`{ a: 1 }`) is edited as a whole, never inside.
    let before: String = lines.get(line)?.chars().take(col).collect();
    before
        .chars()
        .all(|one| one == ' ' || one == '-')
        .then_some(Here { col })
}

fn item_of<'a>(items: &'a [Node], part: &str) -> Option<&'a Node> {
    match part.parse::<usize>() {
        Ok(index) => items.get(index),
        Err(_) => items
            .iter()
            .find(|item| crate::folder::stage_named(item) == Some(part)),
    }
}

/// `{a: {b: value}}` for the parts `a.b`.
fn nested(parts: &[&str], value: &Json) -> Json {
    parts.iter().rev().fold(value.clone(), |inner, part| {
        let mut map = serde_json::Map::new();
        map.insert((*part).to_owned(), inner);
        Json::Object(map)
    })
}

/// The lines an entry takes: its key's, and every one after it indented
/// deeper, or a list's dash at its column. Blank lines at its end are not
/// its own.
fn end_of(lines: &[String], entry: &Entry) -> usize {
    let mut end = entry.line + 1;
    let mut last = end;
    while let Some(line) = lines.get(end) {
        let body = line.trim_start_matches(' ');
        if !body.trim().is_empty() {
            let indent = line.len() - body.len();
            let dash = body.starts_with("- ") || body.trim_end() == "-";
            if indent < entry.col || (indent == entry.col && !dash) {
                break;
            }
            last = end + 1;
        }
        end += 1;
    }
    last
}

fn insert(
    mut lines: Vec<String>,
    here: &Here,
    items: &[(node::Key, Node)],
    name: &str,
    value: &Json,
) -> Option<String> {
    let (key, _) = items.last()?;
    let last = Entry {
        line: key.line?.checked_sub(1)?,
        col: here.col,
        only: false,
    };
    let at = end_of(&lines, &last);
    let new = entry_lines(name, value, here.col);
    let pad = " ".repeat(here.col);
    let new: Vec<String> = new
        .into_iter()
        .enumerate()
        .map(|(at, line)| {
            if at == 0 {
                format!("{pad}{line}")
            } else {
                line
            }
        })
        .collect();
    lines.splice(at..at, new);
    Some(lines.concat())
}

fn replace(
    mut lines: Vec<String>,
    entry: &Entry,
    name: &str,
    old: &Node,
    value: &Json,
) -> Option<String> {
    if let Some(word) = word_of(value) {
        if let (Value::Scalar(was, true), Some(at)) = (&old.value, old.at) {
            if at.line.checked_sub(1)? == entry.line {
                let line = lines.get_mut(entry.line)?;
                let start = line
                    .char_indices()
                    .nth(at.col)
                    .map_or(line.len(), |(byte, _)| byte);
                if line[start..].starts_with(was.as_str()) {
                    line.replace_range(start..start + was.len(), &word);
                    return Some(lines.concat());
                }
            }
        }
    }
    let end = end_of(&lines, entry);
    let first = lines.get(entry.line)?;
    let prefix: String = first.chars().take(entry.col).collect();
    let mut new = entry_lines(name, value, entry.col);
    new[0] = format!("{prefix}{}", new[0]);
    lines.splice(entry.line..end, new);
    Some(lines.concat())
}

fn remove(mut lines: Vec<String>, chain: &[Entry]) -> Option<String> {
    // A map left with no key goes with its own key, up to the top.
    let at = chain
        .iter()
        .rev()
        .skip(1)
        .zip(chain.iter().rev())
        .take_while(|(_, child)| child.only)
        .map(|(parent, _)| *parent)
        .last()
        .unwrap_or(*chain.last()?);
    let first = lines.get(at.line)?;
    if first.chars().take(at.col).any(|one| one != ' ') {
        return None;
    }
    let end = end_of(&lines, &at);
    lines.drain(at.line..end);
    Some(lines.concat())
}

fn word_of(value: &Json) -> Option<String> {
    match value {
        Json::Bool(yes) => Some(yes.to_string()),
        Json::Number(number) => Some(number.to_string()),
        Json::String(text) => Some(scalar(text)),
        _ => None,
    }
}

fn inline(value: &Json) -> Option<String> {
    match value {
        Json::Null => Some("null".to_owned()),
        Json::Array(items) if items.is_empty() => Some("[]".to_owned()),
        Json::Object(fields) if fields.is_empty() => Some("{}".to_owned()),
        Json::Array(_) | Json::Object(_) => None,
        other => word_of(other),
    }
}

/// `name: value` as lines, the first unindented, the rest at their own
/// depth below `col`.
fn entry_lines(name: &str, value: &Json, col: usize) -> Vec<String> {
    let key = scalar(name);
    if let Some(word) = inline(value) {
        return vec![format!("{key}: {word}\n")];
    }
    let mut lines = vec![format!("{key}:\n")];
    block(value, col + 2, &mut lines);
    lines
}

fn block(value: &Json, col: usize, lines: &mut Vec<String>) {
    let pad = " ".repeat(col);
    match value {
        Json::Object(fields) => {
            for (name, value) in fields {
                let mut entry = entry_lines(name, value, col);
                entry[0] = format!("{pad}{}", entry[0]);
                lines.extend(entry);
            }
        }
        Json::Array(items) => {
            for item in items {
                match (item, inline(item)) {
                    (_, Some(word)) => lines.push(format!("{pad}- {word}\n")),
                    (Json::Object(fields), None) => {
                        // What names an item comes first, as it is written by hand.
                        let mut fields: Vec<(&String, &Json)> = fields.iter().collect();
                        fields.sort_by_key(|(name, _)| {
                            !["uses", "name", "agent"].contains(&name.as_str())
                        });
                        for (at, (name, value)) in fields.into_iter().enumerate() {
                            let mut entry = entry_lines(name, value, col + 2);
                            let lead = if at == 0 {
                                format!("{pad}- ")
                            } else {
                                format!("{pad}  ")
                            };
                            entry[0] = format!("{lead}{}", entry[0]);
                            lines.extend(entry);
                        }
                    }
                    (other, None) => lines.push(format!("{pad}- {other}\n")),
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
#[path = "edit_tests.rs"]
mod tests;
