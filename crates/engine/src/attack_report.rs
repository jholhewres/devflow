//! An attack's report for people and tools: markdown, JSON and SARIF 2.1.0,
//! and one issue draft per confirmed hypothesis. What a report carries is
//! held to an allowlist: the fields devflow itself sets (severity, class, a
//! repository path, a line, the run, who confirmed it, the proof's results),
//! and the model's prose through [`prose`], which keeps plain words and the
//! item's own symbols and leaves out every other word. The exploits'
//! strings are taken out first, so a payload never reaches a draft, and no
//! exploit's code is in any of them. devflow publishes none of this: the
//! files are the host's to show and to send where the person says.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{json, Value};

/// The files a report is written as, in its run.
pub const MARKDOWN: &str = "attack-report.md";
pub const JSON: &str = "attack-report.json";
pub const SARIF: &str = "attack-report.sarif";
/// The folder of the issue drafts, one per confirmed hypothesis.
pub const DRAFTS: &str = "drafts";
/// What stands for each word [`prose`] leaves out.
pub const LEFT_OUT: &str = "<…>";
/// The shortest exploit string taken for a payload.
const SHORTEST_PAYLOAD: usize = 6;
/// The shortest run of word characters taken for a secret by its shape.
const SHORTEST_SECRET: usize = 32;
/// The longest symbol of the item's that prose keeps.
const LONGEST_SYMBOL: usize = 40;
/// The most symbols a report keeps.
const MOST_SYMBOLS: usize = 2000;
/// A word of letters and digits this long reads as a token, not prose.
const SHORTEST_OPAQUE: usize = 12;

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

    /// The file this format is written to in the run.
    pub fn file(self) -> &'static str {
        match self {
            Format::Markdown => MARKDOWN,
            Format::Json => JSON,
            Format::Sarif => SARIF,
        }
    }
}

/// What a report's prose is held to: the exploits' strings, taken out, and
/// the item's own symbols, kept.
#[derive(Debug, Default, Clone)]
pub struct Known {
    pub payloads: Vec<String>,
    pub symbols: BTreeSet<String>,
}

impl Known {
    /// The payloads of every exploit a report's run kept, and the symbols
    /// the report names.
    pub fn of(folder: &Path, report: &Value) -> Known {
        Known {
            payloads: payloads(folder, report),
            symbols: report["symbols"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .filter(|one| symbol_shaped(one))
                .map(str::to_owned)
                .collect(),
        }
    }
}

/// The symbols of a diff that prose may name: identifiers outside quoted
/// strings on its lines of code, none of them shaped like a secret. A line
/// whose quotes do not pair loses the rest, never keeps it.
pub fn symbols_in(diff: &str) -> Vec<String> {
    let mut found = BTreeSet::new();
    for line in diff.lines() {
        if line.starts_with("+++") || line.starts_with("---") {
            continue;
        }
        let Some(code) = line.strip_prefix(['+', '-', ' ']) else {
            continue;
        };
        for word in unquoted(code).split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_')) {
            if found.len() < MOST_SYMBOLS && symbol_shaped(word) && !plain_word(word) {
                found.insert(word.to_owned());
            }
        }
    }
    found.into_iter().collect()
}

/// A line of code with its quoted strings taken out; an unpaired quote
/// takes the rest of the line with it.
fn unquoted(code: &str) -> String {
    let mut out = String::new();
    let mut chars = code.chars();
    while let Some(ch) = chars.next() {
        if !matches!(ch, '"' | '\'' | '`') {
            out.push(ch);
            continue;
        }
        let mut closed = false;
        while let Some(inside) = chars.next() {
            if inside == '\\' {
                chars.next();
            } else if inside == ch {
                closed = true;
                break;
            }
        }
        if !closed {
            break;
        }
        out.push(' ');
    }
    out
}

/// An identifier prose may keep when the item's code names it.
fn symbol_shaped(word: &str) -> bool {
    let mut chars = word.chars();
    let starts = chars
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_');
    (2..=LONGEST_SYMBOL).contains(&word.len())
        && starts
        && word
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        && word.chars().filter(char::is_ascii_digit).count() <= 4
        && !secret_shaped(word)
}

/// What an exploit's code sends: its quoted strings, read line by line so
/// an apostrophe in a comment never shifts the rest, an escaped quote read
/// as part of its string, and its unquoted words that look sent (a URL, an
/// escape, a traversal, markup, a long path).
pub fn payloads_in(code: &str) -> Vec<String> {
    // Stands for an escaped quote while a line is split on its quotes.
    const ESCAPED: char = '\u{E000}';
    let mut found: Vec<String> = Vec::new();
    let mut take = |said: &str| {
        let said = said.trim_end_matches('\\');
        if said.chars().count() >= SHORTEST_PAYLOAD {
            found.push(said.to_owned());
        }
    };
    for line in code.lines() {
        for quote in ['"', '\'', '`'] {
            let line = line.replace(&format!("\\{quote}"), &ESCAPED.to_string());
            let parts: Vec<&str> = line.split(quote).collect();
            if parts.len() < 3 {
                continue;
            }
            for (at, part) in parts.iter().enumerate() {
                if at % 2 == 1 && at + 1 < parts.len() {
                    take(&part.replace(ESCAPED, &quote.to_string()));
                    // What an escaped quote holds is sent too.
                    for inner in part.split(ESCAPED).skip(1).step_by(2) {
                        take(inner);
                    }
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
            take(word);
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

/// The names a secret is said under, whole or as a name's last part
/// (`x_api_key`, `accessToken`).
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

/// Whether `name` names a secret, in snake, kebab or camel case.
fn secret_name(name: &str) -> bool {
    let name =
        name.trim_matches(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'));
    let mut camel = String::new();
    for (at, ch) in name.chars().enumerate() {
        if at > 0 && ch.is_ascii_uppercase() {
            camel.push('_');
        }
        camel.push(ch.to_ascii_lowercase());
    }
    [name.to_ascii_lowercase(), camel].iter().any(|name| {
        let name = name.replace('-', "_");
        !name.is_empty()
            && SECRET_NAMES
                .iter()
                .any(|one| name == *one || name.ends_with(&format!("_{one}")))
    })
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
                out.push_str(LEFT_OUT);
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

/// A word of prose: letters, with digits only in a short one (`sha256`),
/// hyphens and apostrophes only between them (`x-api-key`, `don't`), and
/// not a long run whose case changes as a token's does.
fn plain_word(word: &str) -> bool {
    let chars: Vec<char> = word.chars().collect();
    let joins = |at: usize| {
        at > 0
            && at + 1 < chars.len()
            && chars[at - 1].is_alphanumeric()
            && chars[at + 1].is_alphanumeric()
    };
    let shaped = chars.iter().enumerate().all(|(at, ch)| {
        ch.is_alphabetic() || ch.is_ascii_digit() || (matches!(ch, '-' | '\'' | '’') && joins(at))
    });
    let digits = chars.iter().filter(|ch| ch.is_ascii_digit()).count();
    let inner_upper = chars.iter().skip(1).filter(|ch| ch.is_uppercase()).count();
    shaped
        && chars.iter().any(|ch| ch.is_alphabetic())
        && chars.len() <= LONGEST_SYMBOL
        && (digits == 0 || chars.len() < SHORTEST_OPAQUE)
        && !(chars.len() >= 16 && inner_upper >= 4)
}

/// A number of prose: `42`, `1.5`, a version `2.1.0` or `v2.1.0`; never four
/// parts (an address) nor nine digits (a phone).
fn number(word: &str) -> bool {
    let bare = word.strip_prefix('v').unwrap_or(word);
    let parts: Vec<&str> = bare.split(['.', ',']).collect();
    parts.len() <= 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()))
        && bare.chars().filter(char::is_ascii_digit).count() < 9
}

/// What may stand around a word and is not part of it.
const OPENING: [char; 9] = ['(', '[', '"', '\'', '`', '“', '‘', '«', '*'];
const CLOSING: [char; 19] = [
    ')', ']', '"', '\'', '`', '”', '’', '»', '*', '.', ',', ';', ':', '!', '?', '(', '…', '-', '–',
];
/// What of that is kept: sentence punctuation, never a quote or markup.
const KEPT_AROUND: [char; 10] = ['(', ')', '.', ',', ';', ':', '!', '?', '…', '–'];

/// The model's prose as a report may show it: the exploits' strings taken
/// out first, then each word kept only when it is a plain word, a number,
/// or a symbol the item's code names; any other word (code, a URL, a path,
/// a query, an escape, an address, a token) is [`LEFT_OUT`], as is the word
/// after a secret's name or a `Bearer`, and a phone number.
pub fn prose(text: &str, known: &Known) -> String {
    let mut text = text.to_owned();
    for payload in &known.payloads {
        text = text.replace(payload.as_str(), LEFT_OUT);
    }
    let mut said: Vec<(String, String)> = Vec::new();
    let mut hide_next = false;
    let mut named_before = false;
    for piece in text.split_inclusive(char::is_whitespace) {
        let word = piece.trim_end();
        let gap = piece[word.len()..].to_owned();
        if word.is_empty() {
            match said.last_mut() {
                Some(last) => last.1.push_str(&gap),
                None => said.push((String::new(), gap)),
            }
            continue;
        }
        let opened = word.trim_start_matches(OPENING);
        let core = opened.trim_end_matches(CLOSING);
        let before = &word[..word.len() - opened.len()];
        let after = &opened[core.len()..];
        let around =
            |part: &str| -> String { part.chars().filter(|ch| KEPT_AROUND.contains(ch)).collect() };
        let kept = core == LEFT_OUT
            || (!core.is_empty()
                && (plain_word(core) || number(core) || known.symbols.contains(core)));
        let bearer = matches!(core.to_ascii_lowercase().as_str(), "bearer" | "basic");
        let shown = if hide_next {
            LEFT_OUT.to_owned()
        } else if core.is_empty() {
            around(word)
        } else if kept {
            format!("{}{core}{}", around(before), around(after))
        } else {
            format!("{}{LEFT_OUT}{}", around(before), around(after))
        };
        // The value after `X-API-Key:`, `password=`, `token =` or `Bearer`.
        let names = word.ends_with([':', '=']) && secret_name(word.trim_end_matches([':', '=']));
        hide_next = bearer || names || (named_before && matches!(word, ":" | "="));
        named_before = secret_name(core);
        // Words left out one after another are said once.
        if shown == LEFT_OUT && said.last().is_some_and(|(last, _)| last == LEFT_OUT) {
            if gap.contains('\n') {
                if let Some(last) = said.last_mut() {
                    last.1 = gap;
                }
            }
            continue;
        }
        said.push((shown, gap));
    }
    let joined: String = said.into_iter().map(|(word, gap)| word + &gap).collect();
    without_phones(&joined)
}

/// A field devflow sets, kept when it is one of `words`.
fn one_of(value: &Value, words: &[&str]) -> Value {
    match value.as_str() {
        Some(word) if words.contains(&word) => json!(word),
        _ => Value::Null,
    }
}

/// A name devflow or the person set (a class, a repository, a hypothesis'
/// id): kept when it is one word of `[A-Za-z0-9_-]`.
fn name_of(value: &Value) -> Value {
    match value.as_str() {
        Some(word)
            if (1..=LONGEST_SYMBOL).contains(&word.len())
                && word
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
                && !secret_shaped(word) =>
        {
            json!(word)
        }
        _ => Value::Null,
    }
}

/// A scanner's own name for a rule or a package (`GO-2099-0002`,
/// `@scope/pkg`): its tool wrote it, so it keeps the characters names use
/// and nothing that ends a cell or a code span.
fn tool_name(value: &Value) -> Value {
    match value.as_str() {
        Some(word)
            if (1..=120).contains(&word.len())
                && word
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || "._-@/:+".contains(ch))
                && !word.contains("//") =>
        {
            json!(word)
        }
        _ => Value::Null,
    }
}

/// A repository path, relative, with no `..`, nothing that ends a cell or a
/// code span, and no part shaped like a secret.
fn repo_path(value: &Value) -> Value {
    match value.as_str() {
        Some(file)
            if (1..=240).contains(&file.len())
                && !file.starts_with('/')
                && file
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || "._-/[]()@+~,".contains(ch))
                && file
                    .split('/')
                    .all(|part| !matches!(part, "" | "." | "..") && !secret_shaped(part)) =>
        {
            json!(file)
        }
        _ => Value::Null,
    }
}

/// A commit devflow read: its hex.
fn commit(value: &Value) -> Value {
    match value.as_str() {
        Some(hex)
            if (7..=64).contains(&hex.len()) && hex.chars().all(|ch| ch.is_ascii_hexdigit()) =>
        {
            json!(hex)
        }
        _ => Value::Null,
    }
}

const SEVERITIES: [&str; 5] = ["critical", "high", "medium", "low", "info"];
const STATUSES: [&str; 4] = ["confirmed", "refuted", "tried", "not_run"];

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

/// A proof's side as a report shows it: its commit, its result, and why.
fn side(value: &Value, known: &Known) -> Value {
    json!({
        "commit": commit(&value["commit"]),
        "result": one_of(&value["result"], &["red", "green", "skipped", "error"]),
        "reason": prose(text(value, "reason"), known),
    })
}

/// A hypothesis as a report shows it: only fields devflow sets and prose,
/// with no exploit code.
fn shown(one: &Value, known: &Known) -> Value {
    let said = |key: &str| prose(text(one, key), known);
    let proof = &one["proof"];
    json!({
        "id": name_of(&one["id"]), "status": one_of(&one["status"], &STATUSES),
        "severity": one_of(&one["severity"], &SEVERITIES),
        "class": name_of(&one["class"]), "file": repo_path(&one["file"]),
        "line": one["line"].as_u64(),
        "title": said("title"), "reason": said("reason"),
        "impact": said("impact"), "fix": said("fix"),
        "test": one["exploit"]["test"].as_str().map(|test| prose(test, known)),
        "verified_by": one_of(&one["verified"]["by"], &["sandbox", "session"]),
        "proof": (!proof.is_null()).then(|| json!({
            "base": side(&proof["base"], known), "head": side(&proof["head"], known),
            "stack": proof["stack"].as_bool(),
        })),
        "fixes": one["fixes"].as_array().map(|fixes| fixes.iter().map(|fix| json!({
            "repo": name_of(&fix["repo"]), "fix": prose(text(fix, "fix"), known),
        })).collect::<Vec<_>>()),
    })
}

/// The report as JSON: the run, its verdict and numbers, and every
/// hypothesis as [`shown`].
pub fn json_of(report: &Value, known: &Known) -> Value {
    json!({
        "item": report["item"], "run": report["run"], "base": report["base"], "head": report["head"],
        "mode": report["mode"], "verdict": report["verdict"], "counts": report["counts"],
        "metrics": report["metrics"],
        "hypotheses": report["hypotheses"].as_array().into_iter().flatten()
            .map(|one| shown(one, known)).collect::<Vec<_>>(),
        "scanner": {
            "reachable": scanned(report, known, true),
            "rest": scanned(report, known, false),
        },
    })
}

/// The scanner findings the attack called reachable, or the rest: the
/// scanner's own names, and the attack's prose held as a hypothesis' is.
fn scanned(report: &Value, known: &Known, reachable: bool) -> Vec<Value> {
    report["scanner"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|one| (one["reachable"] == true) == reachable)
        .map(|one| {
            let said = |key: &str| prose(text(one, key), known);
            json!({
                "id": name_of(&one["id"]), "tool": name_of(&one["tool"]),
                "rule": tool_name(&one["rule"]), "package": tool_name(&one["package"]),
                "file": repo_path(&one["file"]), "line": one["line"].as_u64(),
                "severity": one_of(&one["severity"], &SEVERITIES),
                "reachable": one["reachable"].as_bool(), "path": said("path"),
                "fix": if text(one, "attacker_fix").is_empty() { said("fix") } else { said("attacker_fix") },
            })
        })
        .collect()
}

/// A field as a markdown cell or line shows it.
fn cell(value: &Value) -> String {
    match value {
        Value::String(said) => said.replace('|', "\\|").replace('\n', " "),
        Value::Null => LEFT_OUT.to_owned(),
        other => other.to_string(),
    }
}

/// The report as markdown.
pub fn markdown(report: &Value, known: &Known) -> String {
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
    let reachable = scanned(report, known, true);
    let rest = scanned(report, known, false);
    if !reachable.is_empty() || !rest.is_empty() {
        out.push_str("\n## Scanner findings untrusted input reaches\n\n");
        if reachable.is_empty() {
            out.push_str("None.\n");
        }
        for one in &reachable {
            out.push_str(&format!(
                "- {} {} `{}` in {} at {}:{}: {}. Fix: {}\n",
                cell(&one["severity"]),
                cell(&one["rule"]),
                cell(&one["package"]),
                cell(&one["tool"]),
                cell(&one["file"]),
                one["line"].as_u64().unwrap_or(1),
                cell(&one["path"]),
                cell(&one["fix"])
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
                cell(&one["severity"]),
                cell(&one["rule"]),
                cell(&one["package"]),
                cell(&one["file"]),
                one["line"].as_u64().unwrap_or(1)
            ));
        }
    }
    let hypotheses: Vec<Value> = report["hypotheses"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|one| shown(one, known))
        .collect();
    let across: Vec<String> = hypotheses
        .iter()
        .filter_map(|one| {
            let fixes: Vec<String> = one["fixes"]
                .as_array()?
                .iter()
                .map(|fix| format!("{}: {}", cell(&fix["repo"]), cell(&fix["fix"])))
                .collect();
            (!fixes.is_empty()).then(|| format!("- {}: {}\n", cell(&one["id"]), fixes.join("; ")))
        })
        .collect();
    if !across.is_empty() {
        out.push_str("\n## Fixes on each side of the flow\n\n");
        out.push_str(&across.concat());
    }
    out.push_str("\n| Status | Severity | Where | Hypothesis | Why |\n|---|---|---|---|---|\n");
    for one in &hypotheses {
        out.push_str(&format!(
            "| {} | {} | `{}:{}` | {} | {} |\n",
            cell(&one["status"]),
            cell(&one["severity"]),
            cell(&one["file"]),
            one["line"],
            cell(&one["title"]),
            cell(&one["reason"]),
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
pub fn sarif(report: &Value, known: &Known) -> Value {
    let results: Vec<Value> = confirmed(report)
        .map(|one| shown(one, known))
        .map(|one| {
            let rule = match one["class"].as_str() {
                Some(class) => format!("attack/{class}"),
                None => "attack".to_owned(),
            };
            json!({
                "ruleId": rule,
                "level": level(text(&one, "severity")),
                "message": { "text": text(&one, "title") },
                "locations": [{ "physicalLocation": {
                    "artifactLocation": { "uri": one["file"].as_str().unwrap_or(".") },
                    "region": { "startLine": one["line"].as_u64().unwrap_or(1).max(1) },
                } }],
                "properties": { "severity": one["severity"], "verifiedBy": one["verified_by"] },
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
/// fix and run, as [`shown`].
pub fn drafts(report: &Value, known: &Known) -> Vec<Value> {
    confirmed(report)
        .map(|one| {
            let one = shown(one, known);
            let title = format!("[security] {}", or_unsaid(&cell(&one["title"])));
            let body = format!(
                "**Severity:** {}\n**Where:** `{}:{}`\n**Found by:** devflow's attack, run {} of {}\n**Confirmed by:** {}\n\n## Impact\n{}\n\n## Fix\n{}\n\n## How it was shown\n{}\n",
                cell(&one["severity"]),
                cell(&one["file"]),
                one["line"],
                text(report, "run"),
                text(report, "item"),
                match text(&one, "verified_by") {
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
    let known = Known::of(folder, report);
    let put = |file: &str, text: &str| -> Result<String, String> {
        crate::attack::put(folder, file, text)?;
        Ok(file.to_owned())
    };
    let mut files = vec![
        put(MARKDOWN, &markdown(report, &known))?,
        put(JSON, &crate::attack::pretty(&json_of(report, &known)))?,
        put(SARIF, &crate::attack::pretty(&sarif(report, &known)))?,
    ];
    for (at, draft) in drafts(report, &known).iter().enumerate() {
        let id = draft["id"]
            .as_str()
            .map_or_else(|| format!("h{}", at + 1), str::to_owned);
        let said = format!("# {}\n\n{}", text(draft, "title"), text(draft, "body"));
        files.push(put(&format!("{DRAFTS}/{id}.md"), &said)?);
    }
    Ok(files)
}

#[cfg(test)]
#[path = "attack_report_tests.rs"]
mod tests;
