//! A dependency scanner's report: `npm audit --json` and `govulncheck
//! -json`. Each vulnerable package is a finding at its package and place
//! (the lockfile, or the line of the checkout that calls into it), with the
//! fix the tool names. Like SARIF, it counts no test as passed.

use std::path::Path;

use serde_json::Value;

use crate::config::Severity;
use crate::verdict::Tested;

use super::sarif::{place, ToolFinding, MOST_TOOL_FINDINGS};
use super::Reported;

/// What `read_from` says once an npm audit report was read.
pub const NPM_AUDIT: &str = "npm audit";
/// What `read_from` says once a govulncheck report was read.
pub const GOVULNCHECK: &str = "govulncheck";
const LONGEST: usize = 300;

fn cut(text: &str) -> String {
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    line.chars().take(LONGEST).collect()
}

fn severity(word: &str) -> Severity {
    match word {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "moderate" | "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

/// `npm audit --json` (report version 2): each vulnerable package at the
/// lockfile, its advisory and the fix npm offers.
pub(super) fn npm_audit(text: &str, cwd: &Path) -> Option<Reported> {
    let report: Value = serde_json::from_str(text).ok()?;
    if report["auditReportVersion"].as_u64() != Some(2) {
        return None;
    }
    let lockfile = ["package-lock.json", "npm-shrinkwrap.json", "package.json"]
        .iter()
        .find_map(|file| place(file, None, cwd))
        .unwrap_or_else(|| "package.json".to_owned());
    let mut reported = Reported::of(Tested {
        read_from: vec![NPM_AUDIT.to_owned()],
        ..Tested::default()
    });
    let vulnerabilities = report["vulnerabilities"].as_object()?;
    for (name, found) in vulnerabilities {
        if reported.found.len() >= MOST_TOOL_FINDINGS {
            break;
        }
        // An advisory of its own, or only through another package.
        let advisory = found["via"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|via| via.is_object());
        let rule = advisory
            .and_then(|via| via["url"].as_str())
            .and_then(|url| url.rsplit('/').next())
            .filter(|id| !id.is_empty())
            .map_or_else(|| format!("{name} (through a dependency)"), str::to_owned);
        let title = advisory
            .and_then(|via| via["title"].as_str())
            .unwrap_or("vulnerable through a dependency");
        let fix = match &found["fixAvailable"] {
            Value::Bool(true) => Some("npm audit fix".to_owned()),
            Value::Object(to) => Some(format!(
                "upgrade {} to {}{}",
                to.get("name").and_then(Value::as_str).unwrap_or(name),
                to.get("version")
                    .and_then(Value::as_str)
                    .unwrap_or("its fixed version"),
                if to.get("isSemVerMajor") == Some(&Value::Bool(true)) {
                    " (a major version)"
                } else {
                    ""
                }
            )),
            _ => None,
        };
        reported.found.push(ToolFinding {
            tool: NPM_AUDIT.to_owned(),
            rule: cut(&rule),
            file: lockfile.clone(),
            line: 1,
            end_line: None,
            severity: severity(found["severity"].as_str().unwrap_or_default()),
            message: cut(&format!(
                "{name} {}: {title}",
                found["range"].as_str().unwrap_or("")
            )),
            package: Some(cut(name)),
            fix: fix.map(|fix| cut(&fix)),
        });
    }
    Some(reported)
}

/// `govulncheck -json`: a stream of messages. Each advisory is kept once, at
/// its most precise trace: a vulnerable function the code calls (high), at
/// the line of the checkout that calls into it, else a package or module it
/// only imports (low), at go.mod.
pub(super) fn govulncheck(text: &str, cwd: &Path) -> Option<Reported> {
    let messages: Vec<Value> = serde_json::Deserializer::from_str(text)
        .into_iter::<Value>()
        .collect::<Result<_, _>>()
        .ok()?;
    let config = messages.iter().find(|one| one.get("config").is_some())?;
    config["config"]["protocol_version"].as_str()?;
    let summaries: Vec<(&str, &str)> = messages
        .iter()
        .filter_map(|one| {
            Some((
                one["osv"]["id"].as_str()?,
                one["osv"]["summary"].as_str().unwrap_or(""),
            ))
        })
        .collect();
    let mut reported = Reported::of(Tested {
        read_from: vec![GOVULNCHECK.to_owned()],
        ..Tested::default()
    });
    let mut kept: Vec<(String, bool)> = Vec::new();
    for finding in messages.iter().filter_map(|one| one.get("finding")) {
        let Some(id) = finding["osv"].as_str() else {
            continue;
        };
        let trace = finding["trace"].as_array().map_or(&[][..], Vec::as_slice);
        let called = trace
            .first()
            .is_some_and(|frame| frame["function"].as_str().is_some());
        match kept.iter().position(|(had, _)| had == id) {
            // A called function says more than an import.
            Some(at) if kept[at].1 || !called => continue,
            Some(at) => {
                kept.remove(at);
                reported.found.remove(at);
            }
            None if reported.found.len() >= MOST_TOOL_FINDINGS => continue,
            None => {}
        }
        let vulnerable = trace.first();
        let module = vulnerable
            .and_then(|frame| frame["module"].as_str())
            .unwrap_or("");
        let package = vulnerable
            .and_then(|frame| frame["package"].as_str())
            .unwrap_or(module);
        // The frame nearest the checkout's own code: where it calls in.
        let (file, line) = trace
            .iter()
            .rev()
            .find_map(|frame| {
                let at = &frame["position"];
                let file = at["filename"].as_str()?;
                let uri = if file.starts_with('/') {
                    format!("file://{file}")
                } else {
                    file.to_owned()
                };
                Some((place(&uri, None, cwd)?, at["line"].as_u64().unwrap_or(1)))
            })
            .unwrap_or_else(|| ("go.mod".to_owned(), 1));
        let function = vulnerable.and_then(|frame| frame["function"].as_str());
        let summary = summaries
            .iter()
            .find(|(osv, _)| *osv == id)
            .map_or("", |(_, summary)| summary);
        let message = match function {
            Some(function) => format!("{summary} (calls {package}.{function})"),
            None => format!("{summary} (imports {package})"),
        };
        reported.found.push(ToolFinding {
            tool: GOVULNCHECK.to_owned(),
            rule: cut(id),
            file,
            line: line.max(1),
            end_line: None,
            severity: if called {
                Severity::High
            } else {
                Severity::Low
            },
            message: cut(&message),
            package: Some(cut(package)),
            fix: finding["fixed_version"]
                .as_str()
                .map(|version| cut(&format!("upgrade {module} to {version}"))),
        });
        kept.push((id.to_owned(), called));
    }
    Some(reported)
}

#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;
