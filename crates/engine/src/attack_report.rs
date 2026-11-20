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

/// What an exploit's code sends: its quoted strings, read line by line so
/// an apostrophe in a comment never shifts the rest, and its unquoted words
/// that look sent (a URL, an escape, a traversal, markup, a long path).
pub fn payloads_in(code: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for line in code.lines() {
        for quote in ['"', '\'', '`'] {
            let parts: Vec<&str> = line.split(quote).collect();
            if parts.len() < 3 {
                continue;
            }
            for (at, part) in parts.iter().enumerate() {
                let inside = at % 2 == 1 && at + 1 < parts.len();
                if inside && part.chars().count() >= SHORTEST_PAYLOAD {
                    found.push((*part).to_owned());
                }
            }
        }
        let words = line.split(|ch: char| {
            ch.is_whitespace()
                || matches!(
                    ch,
                    '(' | ')' | ',' | ';' | '"' | '\'' | '`' | '[' | ']' | '{' | '}'
                )
        });
        for word in words.filter(|word| word.chars().count() >= 8 && looks_sent(word)) {
            found.push(word.to_owned());
        }
    }
    found.sort_by_key(|one| std::cmp::Reverse(one.len()));
    found.dedup();
    found
}

/// An unquoted word that is something sent rather than code.
fn looks_sent(word: &str) -> bool {
    word.contains("://")
        || word.contains('%')
        || word.contains("..")
        || word.contains('<')
        || word.contains("\\x")
        || (word.starts_with('/') && word.matches('/').count() >= 2)
        || (word.contains('@') && word.contains(':'))
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
    // A test's own name is not what it sends.
    let tests: Vec<&str> = report["hypotheses"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|one| one["exploit"]["test"].as_str())
        .collect();
    found.retain(|one| !tests.contains(&one.as_str()));
    found.sort_by_key(|one| std::cmp::Reverse(one.len()));
    found.dedup();
    found
}

/// The names a secret is said under: `name=value`, `name: value`, a query's
/// `?name=value`, a header's `Name: value`; matched whole or as a name's
/// last part (`x_api_key`, `access_token`).
const SECRET_NAMES: [&str; 21] = [
    "password",
    "passwd",
    "pwd",
    "pass",
    "secret",
    "token",
    "api_key",
    "apikey",
    "key",
    "authorization",
    "auth",
    "access_key",
    "private_key",
    "cookie",
    "session",
    "sessionid",
    "sid",
    "signature",
    "sig",
    "credentials",
    "jwt",
];

/// Whether `name` names a secret.
fn secret_name(name: &str) -> bool {
    let name = name
        .trim_matches(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
        .to_ascii_lowercase()
        .replace('-', "_");
    !name.is_empty()
        && SECRET_NAMES
            .iter()
            .any(|one| name == *one || name.ends_with(&format!("_{one}")))
}

/// A word's `name=value` parts with a secret's name, their values taken
/// out: `?token=…&page=2` keeps its page.
fn without_values(word: &str) -> String {
    let mut out = String::new();
    let mut rest = word;
    while !rest.is_empty() {
        let cut = rest.find(['?', '&', ';']).map_or(rest.len(), |at| at + 1);
        let (part, after) = rest.split_at(cut);
        let (body, sep) = match part.char_indices().last() {
            Some((at, '?' | '&' | ';')) => (&part[..at], &part[at..]),
            _ => (part, ""),
        };
        match body.split_once(['=', ':']) {
            Some((name, value))
                if secret_name(name) && !value.is_empty() && !value.starts_with("//") =>
            {
                out.push_str(&body[..name.len() + 1]);
                out.push_str("<redacted>");
            }
            _ => out.push_str(body),
        }
        out.push_str(sep);
        rest = after;
    }
    out
}

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
    let mut hide_line = false;
    for piece in text.split_inclusive(|ch: char| ch.is_whitespace()) {
        let word = piece.trim_end();
        let gap = &piece[word.len()..];
        let lower = word.to_ascii_lowercase();
        let core = lower.trim_matches(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'));
        let said = if (hide_line || hide_next) && !word.is_empty() {
            // `Authorization: Bearer value`: the scheme, then its value.
            hide_next = matches!(core, "bearer" | "basic");
            "<redacted>".to_owned()
        } else if word.ends_with([':', '=']) && secret_name(&word[..word.len() - 1]) {
            // `X-API-Key: value`, `password= value`: the value is next; a
            // cookie header's every pair.
            hide_next = true;
            hide_line = matches!(core, "cookie" | "set_cookie");
            word.to_owned()
        } else if matches!(core, "bearer" | "basic") {
            hide_next = true;
            word.to_owned()
        } else if email_shaped(word) && !word.contains("://") {
            "<email>".to_owned()
        } else if secret_shaped(word) && !word.contains(['?', '=', '&']) && !word.contains("://") {
            "<secret>".to_owned()
        } else {
            let mut said = without_values(word);
            if let Some((scheme, rest)) = said.clone().split_once("://") {
                if let Some((who, host)) = rest.split_once('@') {
                    if who.contains(':') && !who.contains('/') {
                        said = format!("{scheme}://<redacted>@{host}");
                    }
                }
            }
            said
        };
        if gap.contains('\n') {
            hide_line = false;
        }
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
        "scanner": {
            "reachable": scanned(report, payloads, true),
            "rest": scanned(report, payloads, false),
        },
    })
}

/// The scanner findings the attack called reachable, or the rest, each
/// scrubbed as a hypothesis is.
fn scanned(report: &Value, payloads: &[String], reachable: bool) -> Vec<Value> {
    report["scanner"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|one| (one["reachable"] == true) == reachable)
        .map(|one| {
            let said = |key: &str| scrub(text(one, key), payloads);
            json!({
                "id": one["id"], "tool": one["tool"], "rule": one["rule"], "package": one["package"],
                "file": one["file"], "line": one["line"], "severity": one["severity"],
                "reachable": one["reachable"], "path": said("path"),
                "fix": if text(one, "attacker_fix").is_empty() { said("fix") } else { said("attacker_fix") },
            })
        })
        .collect()
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
    let reachable = scanned(report, payloads, true);
    let rest = scanned(report, payloads, false);
    if !reachable.is_empty() || !rest.is_empty() {
        out.push_str("\n## Scanner findings untrusted input reaches\n\n");
        if reachable.is_empty() {
            out.push_str("None.\n");
        }
        for one in &reachable {
            out.push_str(&format!(
                "- {} {} `{}` in {} at {}:{}: {}. Fix: {}\n",
                text(one, "severity"),
                text(one, "rule"),
                text(one, "package"),
                text(one, "tool"),
                text(one, "file"),
                one["line"].as_u64().unwrap_or(1),
                text(one, "path"),
                text(one, "fix")
            ));
        }
        out.push_str(&format!(
            "\nThe other {} scanner findings: not reached, or not said.\n",
            rest.len()
        ));
        if let Some(left) = report["scanner_left_out"].as_u64().filter(|left| *left > 0) {
            out.push_str(&format!(
                "{left} more, the least severe, were past what one attack is given.\n"
            ));
        }
        for one in &rest {
            out.push_str(&format!(
                "- {} {} `{}` at {}:{}\n",
                text(one, "severity"),
                text(one, "rule"),
                text(one, "package"),
                text(one, "file"),
                one["line"].as_u64().unwrap_or(1)
            ));
        }
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
            text(&one, "title").replace('|', "\\|").replace('\n', " "),
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
        crate::attack::put(folder, file, text)?;
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
