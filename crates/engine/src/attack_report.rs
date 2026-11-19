//! An attack's report for people and tools: markdown, JSON and SARIF 2.1.0,
//! and one issue draft per confirmed hypothesis. Every text goes through
//! [`scrub`] first: secrets, tokens, e-mail addresses and phone numbers are
//! taken out, and so is every string the exploits send, so a payload never
//! reaches a draft; no exploit's code is in any of them. devflow publishes
//! none of this: the files are the host's to show and to send where the
//! person says.

use std::path::Path;

use serde_json::{json, Value};

/// The files a report is written as, in its run.
pub const MARKDOWN: &str = "attack-report.md";
pub const JSON: &str = "attack-report.json";
pub const SARIF: &str = "attack-report.sarif";
/// The folder of the issue drafts, one per confirmed hypothesis.
pub const DRAFTS: &str = "drafts";
/// The shortest exploit string taken for a payload.
const SHORTEST_PAYLOAD: usize = 6;
/// The shortest run of word characters taken for a secret by its shape.
const SHORTEST_SECRET: usize = 32;

/// The formats a report is asked in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Markdown,
    Json,
    Sarif,
}

impl Format {
    pub fn of(word: &str) -> Option<Format> {
        match word {
            "md" | "markdown" => Some(Format::Markdown),
            "json" => Some(Format::Json),
            "sarif" => Some(Format::Sarif),
            _ => None,
        }
    }
}

/// The strings an exploit's code quotes: what it sends, kept out of every
/// text the report is made of.
pub fn payloads_in(code: &str) -> Vec<String> {
    let mut found = Vec::new();
    for quote in ['"', '\'', '`'] {
        let mut parts = code.split(quote);
        parts.next();
        // Every other part is inside the quotes.
        for (at, part) in parts.enumerate() {
            if at % 2 == 0 && part.chars().count() >= SHORTEST_PAYLOAD && !part.contains('\n') {
                found.push(part.to_owned());
            }
        }
    }
    found.sort_by_key(|one| std::cmp::Reverse(one.len()));
    found.dedup();
    found
}

/// The payloads of every exploit a report's run kept.
pub fn payloads(folder: &Path, report: &Value) -> Vec<String> {
    let mut found: Vec<String> = report["hypotheses"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|one| one["exploit"]["saved"].as_str())
        .filter_map(|saved| crate::fsguard::resolve(folder, saved).ok())
        .filter_map(|at| std::fs::File::open(at).ok())
        .filter_map(|file| crate::fsguard::read_within(file, 64 * 1024).ok().flatten())
        .flat_map(|raw| payloads_in(&String::from_utf8_lossy(&raw)))
        .collect();
    found.sort_by_key(|one| std::cmp::Reverse(one.len()));
    found.dedup();
    found
}

/// The names a secret is said under, as `name=value` or `name: value`.
const SECRET_NAMES: [&str; 10] = [
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "access_key",
    "private_key",
];
/// The prefixes a token is known by.
const TOKEN_PREFIXES: [&str; 8] = [
    "ghp_",
    "gho_",
    "github_pat_",
    "sk-",
    "xoxb-",
    "xoxp-",
    "AKIA",
    "AIza",
];

fn word_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '+' | '/' | '=' | '.')
}

/// A word that is a secret by its shape: a known token's prefix, a JWT, or
/// a long run of letters and digits mixed (a git commit's hex aside).
fn secret_shaped(word: &str) -> bool {
    let core = word.trim_matches(|ch: char| !ch.is_ascii_alphanumeric());
    if TOKEN_PREFIXES
        .iter()
        .any(|prefix| core.starts_with(prefix) && core.len() >= prefix.len() + 12)
    {
        return true;
    }
    if core.starts_with("eyJ") && core.matches('.').count() == 2 && core.len() >= 20 {
        return true;
    }
    let commit = (7..=40).contains(&core.len()) && core.chars().all(|ch| ch.is_ascii_hexdigit());
    core.len() >= SHORTEST_SECRET
        && !commit
        && core.chars().any(|ch| ch.is_ascii_digit())
        && core.chars().any(|ch| ch.is_ascii_alphabetic())
}

/// A word that is an e-mail address.
fn email_shaped(word: &str) -> bool {
    let core = word.trim_matches(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '@'));
    match core.split_once('@') {
        Some((user, host)) => !user.is_empty() && host.contains('.') && !host.starts_with('.'),
        None => false,
    }
}

/// Phone numbers taken out: a run of digits, spaces and `+ ( ) - .` that
/// holds nine digits or more.
fn without_phones(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::new();
    let mut at = 0;
    while at < chars.len() {
        let starts = chars[at].is_ascii_digit() || (chars[at] == '+' || chars[at] == '(');
        if starts {
            let mut end = at;
            let mut digits = 0;
            while end < chars.len()
                && (chars[end].is_ascii_digit()
                    || matches!(chars[end], ' ' | '+' | '(' | ')' | '-' | '.'))
            {
                if chars[end].is_ascii_digit() {
                    digits += 1;
                }
                end += 1;
            }
            // A run that is part of a longer word (a hash, a stamp) stays.
            let inside_word = (at > 0 && chars[at - 1].is_ascii_alphanumeric())
                || (end < chars.len() && chars[end].is_ascii_alphabetic());
            if digits >= 9 && !inside_word {
                let trailing: String = chars[at..end]
                    .iter()
                    .rev()
                    .take_while(|ch| matches!(ch, ' ' | '.' | '-' | ')'))
                    .collect();
                out.push_str("<phone>");
                out.extend(trailing.chars().rev());
                at = end;
                continue;
            }
        }
        out.push(chars[at]);
        at += 1;
    }
    out
}

/// A text with its secrets, tokens, e-mail addresses, phone numbers and
/// the exploits' payloads taken out.
pub fn scrub(text: &str, payloads: &[String]) -> String {
    let mut text = text.to_owned();
    for payload in payloads {
        text = text.replace(payload.as_str(), "<payload>");
    }
    let mut out = String::with_capacity(text.len());
    let mut hide_next = false;
    for piece in text.split_inclusive(|ch: char| ch.is_whitespace()) {
        let word = piece.trim_end();
        let gap = &piece[word.len()..];
        let lower = word.to_ascii_lowercase();
        let core = lower.trim_matches(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'));
        let named = SECRET_NAMES.iter().any(|name| lower.contains(name));
        let value_at = word.find(['=', ':']).filter(|at| {
            !word[at + 1..]
                .trim_matches(|ch: char| !word_char(ch))
                .is_empty()
        });
        let said = if hide_next && !word.is_empty() {
            // `Authorization: Bearer value`: the scheme, then its value.
            hide_next = matches!(core, "bearer" | "basic");
            "<redacted>".to_owned()
        } else if word.contains("://") {
            match word.split_once("://") {
                Some((scheme, rest)) => match rest.split_once('@') {
                    Some((who, host)) if who.contains(':') => {
                        format!("{scheme}://<redacted>@{host}")
                    }
                    _ => word.to_owned(),
                },
                None => word.to_owned(),
            }
        } else if let (true, Some(at)) = (named, value_at) {
            // `password=value`, `token:value`: the value goes.
            format!("{}<redacted>", &word[..=at])
        } else if named && (word.ends_with([':', '=']) || SECRET_NAMES.contains(&core))
            || matches!(core, "bearer" | "basic")
        {
            // `password: value`, `Bearer value`: the next word goes.
            hide_next = true;
            word.to_owned()
        } else if email_shaped(word) {
            "<email>".to_owned()
        } else if secret_shaped(word) {
            "<secret>".to_owned()
        } else {
            word.to_owned()
        };
        out.push_str(&said);
        out.push_str(gap);
    }
    without_phones(&out)
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or_default()
}

fn confirmed(report: &Value) -> impl Iterator<Item = &Value> {
    report["hypotheses"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|one| one["status"] == "confirmed")
}

/// A hypothesis as a report shows it: scrubbed, with no exploit code.
fn shown(one: &Value, payloads: &[String]) -> Value {
    let said = |key: &str| scrub(text(one, key), payloads);
    json!({
        "id": one["id"], "status": one["status"], "severity": one["severity"],
        "class": one["class"], "file": one["file"], "line": one["line"],
        "title": said("title"), "reason": said("reason"),
        "impact": said("impact"), "fix": said("fix"),
        "test": one["exploit"]["test"].as_str().map(|test| scrub(test, payloads)),
        "verified_by": one["verified"]["by"], "proof": one["proof"],
    })
}

/// The report as JSON: the run, its verdict and numbers, and every
/// hypothesis scrubbed.
pub fn json_of(report: &Value, payloads: &[String]) -> Value {
    json!({
        "item": report["item"], "run": report["run"], "base": report["base"], "head": report["head"],
        "mode": report["mode"], "verdict": report["verdict"], "counts": report["counts"],
        "metrics": report["metrics"],
        "hypotheses": report["hypotheses"].as_array().into_iter().flatten()
            .map(|one| shown(one, payloads)).collect::<Vec<_>>(),
    })
}

/// The report as markdown.
pub fn markdown(report: &Value, payloads: &[String]) -> String {
    let counts = &report["counts"];
    let mut out = format!(
        "# Attack report: {}\n\nRun {}, {}..{}. Verdict: **{}**. {} confirmed, {} refuted, {} tried, {} not run.\n",
        text(report, "item"),
        text(report, "run"),
        text(report, "base").chars().take(12).collect::<String>(),
        text(report, "head").chars().take(12).collect::<String>(),
        text(report, "verdict"),
        counts["confirmed"],
        counts["refuted"],
        counts["tried"],
        counts["not_run"],
    );
    let metrics = &report["metrics"];
    if !metrics.is_null() {
        out.push_str(&format!(
            "Cost US$ {:.2}, {} min.\n",
            metrics["cost_usd"].as_f64().unwrap_or_default(),
            metrics["duration_ms"].as_u64().unwrap_or_default() / 60_000
        ));
    }
    out.push_str("\n| Status | Severity | Where | Hypothesis | Why |\n|---|---|---|---|---|\n");
    for one in report["hypotheses"].as_array().into_iter().flatten() {
        let one = shown(one, payloads);
        out.push_str(&format!(
            "| {} | {} | `{}:{}` | {} | {} |\n",
            text(&one, "status"),
            text(&one, "severity"),
            text(&one, "file"),
            one["line"],
            text(&one, "title").replace('|', "\\|"),
            text(&one, "reason").replace('|', "\\|").replace('\n', " "),
        ));
    }
    out
}

fn level(severity: &str) -> &'static str {
    match severity {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

/// The confirmed hypotheses as SARIF 2.1.0, each at its file and line.
pub fn sarif(report: &Value, payloads: &[String]) -> Value {
    let results: Vec<Value> = confirmed(report)
        .map(|one| {
            let rule = match text(one, "class") {
                "" => "attack".to_owned(),
                class => format!("attack/{class}"),
            };
            json!({
                "ruleId": rule,
                "level": level(text(one, "severity")),
                "message": { "text": scrub(text(one, "title"), payloads) },
                "locations": [{ "physicalLocation": {
                    "artifactLocation": { "uri": text(one, "file") },
                    "region": { "startLine": one["line"].as_u64().unwrap_or(1).max(1) },
                } }],
                "properties": { "severity": one["severity"], "verifiedBy": one["verified"]["by"] },
            })
        })
        .collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": "devflow-attack", "version": env!("CARGO_PKG_VERSION") } },
            "results": results,
        }],
    })
}

/// One issue draft per confirmed hypothesis: its title, severity, impact,
/// fix and run, scrubbed.
pub fn drafts(report: &Value, payloads: &[String]) -> Vec<Value> {
    confirmed(report)
        .map(|one| {
            let one = shown(one, payloads);
            let title = format!("[security] {}", text(&one, "title"));
            let body = format!(
                "**Severity:** {}\n**Where:** `{}:{}`\n**Found by:** devflow's attack, run {} of {}\n**Confirmed by:** {}\n\n## Impact\n{}\n\n## Fix\n{}\n\n## How it was shown\n{}\n",
                text(&one, "severity"),
                text(&one, "file"),
                one["line"],
                text(report, "run"),
                text(report, "item"),
                match text(&one, "verified_by") {
                    "" => "the session's run of its exploit test",
                    "sandbox" => "devflow's sandbox, running its exploit test",
                    _ => "the session's run of its exploit test",
                },
                or_unsaid(text(&one, "impact")),
                or_unsaid(text(&one, "fix")),
                or_unsaid(text(&one, "reason")),
            );
            json!({ "id": one["id"], "title": title, "severity": one["severity"], "body": body })
        })
        .collect()
}

fn or_unsaid(said: &str) -> &str {
    if said.trim().is_empty() {
        "Not said by the attack."
    } else {
        said
    }
}

/// The report written in its run as markdown, JSON and SARIF, and its
/// drafts under [`DRAFTS`]; the files' names, relative to the run.
pub fn written(folder: &Path, report: &Value) -> Result<Vec<String>, String> {
    let payloads = payloads(folder, report);
    let put = |file: &str, text: &str| -> Result<String, String> {
        let at = folder.join(file);
        if let Some(parent) = at.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| format!("{}: {err}", parent.display()))?;
        }
        std::fs::write(&at, text).map_err(|err| format!("{}: {err}", at.display()))?;
        Ok(file.to_owned())
    };
    let pretty = |value: &Value| serde_json::to_string_pretty(value).unwrap_or_default() + "\n";
    let mut files = vec![
        put(MARKDOWN, &markdown(report, &payloads))?,
        put(JSON, &pretty(&json_of(report, &payloads)))?,
        put(SARIF, &pretty(&sarif(report, &payloads)))?,
    ];
    for draft in drafts(report, &payloads) {
        let id: String = text(&draft, "id")
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
            .collect();
        let said = format!("# {}\n\n{}", text(&draft, "title"), text(&draft, "body"));
        files.push(put(&format!("{DRAFTS}/{id}.md"), &said)?);
    }
    Ok(files)
}

#[cfg(test)]
#[path = "attack_report_tests.rs"]
mod tests;
