//! SARIF 2.1.0, what a static analyser writes (semgrep, gosec, trivy,
//! gitleaks, CodeQL, …): each result a finding at its file and line. A SARIF
//! report counts no test as passed: it is read for what it found, and a tool
//! that says its own run failed counts as one failure.

use std::path::Path;

use serde::Serialize;
use serde_json::Value;

use crate::config::Severity;
use crate::verdict::{FailedTest, Tested};

use super::Reported;

/// The most findings one run's reports keep: a review's ceiling, not a lint
/// run's.
pub const MOST_TOOL_FINDINGS: usize = crate::findings::MOST_FINDINGS;
/// What `read_from` says once a SARIF report was read.
pub const SARIF: &str = "SARIF";
const LONGEST_NAME: usize = 200;
const LONGEST_MESSAGE: usize = 1000;

/// One result of a static analyser, at a file of the checkout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToolFinding {
    /// The tool's name, as its report says it: `Semgrep OSS`.
    pub tool: String,
    pub rule: String,
    /// Relative to the checkout's root, resolved and checked inside it.
    pub file: String,
    pub line: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u64>,
    pub severity: Severity,
    pub message: String,
}

impl ToolFinding {
    /// One line, as a comment or a packet says it.
    pub fn said(&self) -> String {
        said(
            &self.file,
            self.line,
            &self.rule,
            self.severity.word(),
            &self.tool,
        )
    }
}

/// A tool's finding on one line, from its parts as evidence.json keeps them.
pub fn said(file: &str, line: u64, rule: &str, severity: &str, tool: &str) -> String {
    format!("`{file}:{line}` {rule} ({severity}, {tool})")
}

/// A report's text as SARIF, or `None` when it is not one. `cwd` is the
/// checkout: a location outside it, absolute, or climbing out with `..` is
/// left out, never read.
pub(super) fn from_json(text: &str, cwd: &Path) -> Option<Reported> {
    let report = sarif(text)?;
    let runs = report["runs"].as_array()?;
    let mut reported = Reported::of(Tested {
        read_from: vec![SARIF.to_owned()],
        ..Tested::default()
    });
    for run in runs {
        let tool = cut(
            text_at(run, &["tool", "driver", "name"]).unwrap_or("a SARIF tool"),
            LONGEST_NAME,
        );
        for failed in failed_invocations(run) {
            reported.tested.failed += 1;
            if reported.tested.failures.len() < crate::verdict::MOST_FAILURES_KEPT {
                reported.tested.failures.push(FailedTest {
                    name: format!("{tool} run"),
                    file: None,
                    message: super::short(&failed),
                });
            }
        }
        let rules = run["tool"]["driver"]["rules"]
            .as_array()
            .map_or(&[][..], Vec::as_slice);
        for result in run["results"].as_array().into_iter().flatten() {
            if reported.found.len() >= MOST_TOOL_FINDINGS {
                return Some(reported);
            }
            if let Some(found) = finding(&tool, rules, run, result, cwd) {
                reported.found.push(found);
            }
        }
    }
    Some(reported)
}

/// A text as a SARIF 2.x report: an object with `runs` and its version.
fn sarif(text: &str) -> Option<Value> {
    let report: Value = serde_json::from_str(text).ok()?;
    let version = report.get("version").and_then(Value::as_str)?;
    (report.get("runs")?.is_array() && version.starts_with("2.")).then_some(report)
}

/// What a SARIF report may carry of the files it read: the code a result
/// quotes (where a secret scanner puts the secret it found), and a file's
/// or a fix's whole content.
const QUOTED: [&str; 4] = ["snippet", "contextRegion", "contents", "insertedContent"];

/// A SARIF report as it is kept, without [`QUOTED`]. `None` when the text is
/// not SARIF or quotes nothing, so it is kept as it is.
pub fn without_snippets(text: &str) -> Option<String> {
    let mut report = sarif(text)?;
    fn strip(value: &mut Value) -> bool {
        match value {
            Value::Object(fields) => {
                let mut cut = false;
                for key in QUOTED {
                    cut |= fields.remove(key).is_some();
                }
                fields.values_mut().fold(cut, |cut, one| strip(one) | cut)
            }
            Value::Array(items) => items.iter_mut().fold(false, |cut, one| strip(one) | cut),
            _ => false,
        }
    }
    strip(&mut report)
        .then(|| serde_json::to_string_pretty(&report).ok())
        .flatten()
}

/// What a run's invocations said when one of them did not succeed.
fn failed_invocations(run: &Value) -> Vec<String> {
    run["invocations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|invocation| invocation["executionSuccessful"] == Value::Bool(false))
        .map(|invocation| {
            invocation["toolExecutionNotifications"]
                .as_array()
                .into_iter()
                .flatten()
                .find_map(|notice| text_at(notice, &["message", "text"]))
                .unwrap_or("the tool says its run did not succeed")
                .to_owned()
        })
        .collect()
}

fn finding(
    tool: &str,
    rules: &[Value],
    run: &Value,
    result: &Value,
    cwd: &Path,
) -> Option<ToolFinding> {
    let rule_id = result["ruleId"]
        .as_str()
        .or_else(|| text_at(result, &["rule", "id"]));
    let rule = result["ruleIndex"]
        .as_u64()
        .and_then(|at| rules.get(usize::try_from(at).ok()?))
        .or_else(|| rules.iter().find(|one| one["id"].as_str() == rule_id))
        .unwrap_or(&Value::Null);
    let physical = &result["locations"][0]["physicalLocation"];
    let artifact = &physical["artifactLocation"];
    let base = artifact["uriBaseId"]
        .as_str()
        .and_then(|id| text_at(run, &["originalUriBaseIds", id, "uri"]));
    let file = place(artifact["uri"].as_str()?, base, cwd)?;
    let region = &physical["region"];
    let line = region["startLine"]
        .as_u64()
        .filter(|line| *line > 0)
        .unwrap_or(1);
    Some(ToolFinding {
        tool: tool.to_owned(),
        rule: cut(rule_id.unwrap_or("unnamed"), LONGEST_NAME),
        file,
        line,
        end_line: region["endLine"].as_u64().filter(|end| *end > line),
        severity: severity_of(result, rule),
        message: cut(
            text_at(result, &["message", "text"])
                .or_else(|| text_at(rule, &["shortDescription", "text"]))
                .unwrap_or_default(),
            LONGEST_MESSAGE,
        ),
    })
}

/// A result's severity: its `security-severity` score when the tool gives
/// one (the CVSS-like number GitHub reads), else its level, else the rule's
/// default level, else SARIF's own default, `warning`.
pub fn severity_of(result: &Value, rule: &Value) -> Severity {
    let score = [result, rule].iter().find_map(|one| {
        let said = &one["properties"]["security-severity"];
        said.as_f64()
            .or_else(|| said.as_str().and_then(|text| text.trim().parse().ok()))
    });
    if let Some(score) = score {
        return match score {
            s if s >= 9.0 => Severity::Critical,
            s if s >= 7.0 => Severity::High,
            s if s >= 4.0 => Severity::Medium,
            s if s > 0.0 => Severity::Low,
            _ => Severity::Info,
        };
    }
    let level = result["level"]
        .as_str()
        .or_else(|| text_at(rule, &["defaultConfiguration", "level"]))
        .unwrap_or("warning");
    match level {
        "error" => Severity::High,
        "note" => Severity::Low,
        "none" => Severity::Info,
        _ => Severity::Medium,
    }
}

/// Where a result is, relative to `root`, or `None` when it is not a file
/// of the checkout. `uri` is read against `base` (the run's
/// `originalUriBaseIds`) when one is given; a `file://` URI must lead inside
/// `root`; any other absolute path, another scheme or a `..` part is
/// refused; what is left is resolved through symlinks and kept inside
/// `root`.
pub fn place(uri: &str, base: Option<&str>, root: &Path) -> Option<String> {
    let uri = match base {
        Some(base) if !uri.contains(':') && !uri.starts_with('/') => {
            format!("{}/{uri}", base.trim_end_matches('/'))
        }
        _ => uri.to_owned(),
    };
    let decoded = decoded(&uri)?;
    let relative = match decoded.strip_prefix("file://") {
        Some(rest) => {
            let path = rest.strip_prefix("localhost").unwrap_or(rest);
            if !path.starts_with('/') {
                return None;
            }
            let root = root.canonicalize().ok()?;
            let inside = Path::new(path).strip_prefix(&root).ok()?;
            inside.to_str()?.to_owned()
        }
        None if decoded.starts_with('/') || decoded.starts_with('\\') || decoded.contains(':') => {
            return None
        }
        None => decoded,
    };
    let relative = relative.trim_start_matches("./");
    let parts: Vec<&str> = relative.split(['/', '\\']).collect();
    if relative.is_empty() || parts.contains(&"..") {
        return None;
    }
    let resolved = crate::fsguard::resolve(root, relative).ok()?;
    let root = root.canonicalize().ok()?;
    resolved
        .strip_prefix(&root)
        .ok()
        .and_then(Path::to_str)
        .filter(|inside| !inside.is_empty())
        .map(str::to_owned)
}

/// `%XX` escapes undone, or `None` when one is broken or the text is not
/// UTF-8 after: a path is never guessed at.
fn decoded(uri: &str) -> Option<String> {
    let bytes = uri.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let hex = std::str::from_utf8(bytes.get(at + 1..at + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(out)
        .ok()
        .filter(|text| !text.contains('\0'))
}

fn text_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter()
        .try_fold(value, |at, key| at.get(*key))?
        .as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

fn cut(text: &str, most: usize) -> String {
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.chars().count() > most {
        let kept: String = line.chars().take(most).collect();
        format!("{kept}…")
    } else {
        line
    }
}
