//! Which fields carry the version, and reading or writing them.

use std::path::Path;

use serde_json::Value;

use crate::read_json;

/// A JSON file and the pointers of its version fields. A pointer with `*`
/// stands for every item of that array.
pub const JSON: [(&str, &[&str]); 3] = [
    (".claude-plugin/plugin.json", &["/version"]),
    (
        ".claude-plugin/marketplace.json",
        &["/metadata/version", "/plugins/*/version"],
    ),
    ("gemini-extension.json", &["/version"]),
];

/// The Cargo workspace's own line, and the engine's version where the
/// workspace depends on it.
const CARGO: &str = "Cargo.toml";

pub fn version(root: &Path) -> Result<String, String> {
    let raw = std::fs::read_to_string(root.join("VERSION")).map_err(|e| format!("VERSION: {e}"))?;
    let version = raw.trim().trim_start_matches('v').to_owned();
    if version.is_empty() {
        return Err("VERSION is empty".to_owned());
    }
    Ok(version)
}

/// Every version field found, as (where, value).
pub fn found(root: &Path) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for (file, pointers) in JSON {
        let doc = read_json(&root.join(file))?;
        for pointer in pointers.iter() {
            for (at, value) in at_pointer(&doc, pointer) {
                out.push((
                    format!("{file} {at}"),
                    value.as_str().unwrap_or_default().to_owned(),
                ));
            }
        }
    }
    let cargo = std::fs::read_to_string(root.join(CARGO)).map_err(|e| format!("{CARGO}: {e}"))?;
    for (at, value) in cargo_versions(&cargo) {
        out.push((format!("{CARGO} {at}"), value));
    }
    Ok(out)
}

/// Fails with every disagreement listed.
pub fn check(root: &Path, tag: Option<&str>) -> Result<String, String> {
    let version = version(root)?;
    let mut problems = Vec::new();
    if let Some(tag) = tag {
        if tag.trim_start_matches('v') != version {
            problems.push(format!("tag {tag} is not VERSION {version}"));
        }
    }
    for (at, value) in found(root)? {
        if value != version {
            problems.push(format!("{at} is {value:?}, VERSION is {version}"));
        }
    }
    if problems.is_empty() {
        Ok(version)
    } else {
        Err(format!(
            "versions disagree (run `cargo xtask version-sync`):\n  {}",
            problems.join("\n  ")
        ))
    }
}

/// Rewrites every field to `VERSION`.
pub fn write(root: &Path) -> Result<String, String> {
    let version = version(root)?;
    for (file, pointers) in JSON {
        let path = root.join(file);
        let mut doc = read_json(&path)?;
        for pointer in pointers.iter() {
            set_at_pointer(&mut doc, pointer, &version);
        }
        let text = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())? + "\n";
        std::fs::write(&path, text).map_err(|e| format!("{file}: {e}"))?;
    }
    let path = root.join(CARGO);
    let cargo = std::fs::read_to_string(&path).map_err(|e| format!("{CARGO}: {e}"))?;
    std::fs::write(&path, cargo_with(&cargo, &version)).map_err(|e| format!("{CARGO}: {e}"))?;
    Ok(version)
}

fn at_pointer<'a>(doc: &'a Value, pointer: &str) -> Vec<(String, &'a Value)> {
    match pointer.split_once("/*") {
        None => doc
            .pointer(pointer)
            .map(|value| vec![(pointer.to_owned(), value)])
            .unwrap_or_default(),
        Some((list, rest)) => doc
            .pointer(list)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .enumerate()
                    .filter_map(|(at, item)| {
                        item.pointer(rest)
                            .map(|value| (format!("{list}/{at}{rest}"), value))
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn set_at_pointer(doc: &mut Value, pointer: &str, version: &str) {
    match pointer.split_once("/*") {
        None => {
            if let Some(value) = doc.pointer_mut(pointer) {
                *value = Value::from(version);
            }
        }
        Some((list, rest)) => {
            if let Some(items) = doc.pointer_mut(list).and_then(Value::as_array_mut) {
                for item in items {
                    if let Some(value) = item.pointer_mut(rest) {
                        *value = Value::from(version);
                    }
                }
            }
        }
    }
}

/// The version lines a release depends on: `[workspace.package]`'s, and the
/// engine's under `[workspace.dependencies]`.
pub fn cargo_versions(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut section = "";
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            section = trimmed;
            continue;
        }
        if section == "[workspace.package]" && trimmed.starts_with("version") {
            if let Some(value) = quoted(trimmed) {
                out.push(("[workspace.package] version".to_owned(), value));
            }
        }
        if section == "[workspace.dependencies]" && trimmed.starts_with("devflow-engine") {
            if let Some(value) = trimmed.split("version").nth(1).and_then(quoted) {
                out.push(("[workspace.dependencies] devflow-engine".to_owned(), value));
            }
        }
    }
    out
}

fn cargo_with(text: &str, version: &str) -> String {
    let mut section = String::new();
    let mut out = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            section = trimmed.to_owned();
        }
        let rewritten = match section.as_str() {
            "[workspace.package]" if trimmed.starts_with("version") => {
                format!("version = \"{version}\"")
            }
            "[workspace.dependencies]" if trimmed.starts_with("devflow-engine") => {
                replace_quoted_after(line, "version", version)
            }
            _ => line.to_owned(),
        };
        out.push_str(&rewritten);
        out.push('\n');
    }
    out
}

/// The first `"…"` in `text`.
fn quoted(text: &str) -> Option<String> {
    let start = text.find('"')? + 1;
    let end = start + text[start..].find('"')?;
    Some(text[start..end].to_owned())
}

fn replace_quoted_after(line: &str, key: &str, version: &str) -> String {
    let Some(at) = line.find(key) else {
        return line.to_owned();
    };
    let (head, tail) = line.split_at(at);
    let Some(open) = tail.find('"') else {
        return line.to_owned();
    };
    let Some(close) = tail[open + 1..].find('"') else {
        return line.to_owned();
    };
    format!(
        "{head}{}\"{version}\"{}",
        &tail[..open],
        &tail[open + close + 2..]
    )
}

#[cfg(test)]
#[path = "sync_tests.rs"]
mod tests;
