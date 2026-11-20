//! A generic repertoire of attack inputs by class: each case a neutral
//! input and what safe code does with it, made into a test table a project
//! fills in. A project keeps its own cases beside it, in devflow's folder,
//! and only from a person on a terminal (`devflow payloads add`).
//!
//! Neutral: a case names no real host, address or person. A URL's host is
//! loopback or private on port 1, or a name that resolves nowhere; a bare
//! address leads inside; no name or e-mail address ends in a real place. A
//! table run on any machine reaches nothing.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Each class devflow ships, and its cases.
pub const SHIPPED: [(&str, &str); 8] = [
    ("ssrf", include_str!("../../../flow/payloads/ssrf.json")),
    ("redos", include_str!("../../../flow/payloads/redos.json")),
    (
        "traversal",
        include_str!("../../../flow/payloads/traversal.json"),
    ),
    ("sqli", include_str!("../../../flow/payloads/sqli.json")),
    ("nosqli", include_str!("../../../flow/payloads/nosqli.json")),
    ("xxe", include_str!("../../../flow/payloads/xxe.json")),
    (
        "deserialization",
        include_str!("../../../flow/payloads/deserialization.json"),
    ),
    (
        PROMPT_INJECTION,
        include_str!("../../../flow/payloads/prompt-injection.json"),
    ),
];

/// The class whose cases go to a message builder, not to a check.
pub const PROMPT_INJECTION: &str = "prompt-injection";
/// Who wrote a prompt-injection case's text.
pub const SOURCES: [&str; 3] = ["user", "tool", "document"];

/// What safe code does with a case: refuses it, takes it as plain data,
/// answers within the class's time, or (a prompt's text) keeps it as data in
/// its writer's role.
pub const WANTS: [&str; 4] = ["rejected", "inert", "fast", "data"];
/// The time a `fast` case has when its class says none.
const WITHIN_MS: u64 = 1000;
const MOST_INPUT: usize = 2000;
const MOST_TIMES: u32 = 100_000;
const MOST_KEPT: usize = 200;
/// The most cases one attack proposes.
pub const MOST_PROPOSED: usize = 20;

/// One case: `input` (repeated `times`, then `then`) and what safe code does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub id: String,
    pub input: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub times: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub then: Option<String>,
    /// Who wrote it, for a prompt-injection case: a user, a tool, a document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    pub want: String,
}

/// A class of cases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Class {
    pub class: String,
    pub about: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub within_ms: Option<u64>,
    pub cases: Vec<Case>,
}

/// The classes devflow ships.
pub fn names() -> Vec<&'static str> {
    SHIPPED.iter().map(|(name, _)| *name).collect()
}

fn unknown(class: &str) -> String {
    format!("no payload class `{class}`: {} are", names().join(", "))
}

/// The class as devflow ships it.
pub fn shipped(class: &str) -> Result<Class, String> {
    let (_, text) = SHIPPED
        .iter()
        .find(|(name, _)| *name == class)
        .ok_or_else(|| unknown(class))?;
    serde_json::from_str(text).map_err(|err| format!("{class}: {err}"))
}

/// Where a project keeps its own cases of `class`.
pub fn kept_path(root: &Path, class: &str) -> String {
    format!("{}/payloads/{class}.json", crate::folder::dir(root))
}

/// The project's own cases of `class`, each held to what a shipped one is.
pub fn kept(root: &Path, class: &str) -> Result<Vec<Case>, String> {
    shipped(class)?;
    let relative = kept_path(root, class);
    let Some(text) = crate::review::text_in(root, &relative, 1024 * 1024, "payloads")? else {
        return Ok(Vec::new());
    };
    let cases: Vec<Case> =
        serde_json::from_str(&text).map_err(|err| format!("{relative}: {err}"))?;
    for case in &cases {
        checked_in(class, case).map_err(|why| format!("{relative}: {why}"))?;
    }
    Ok(cases)
}

/// The class with the project's kept cases after devflow's.
pub fn class(root: &Path, class: &str) -> Result<Class, String> {
    let mut found = shipped(class)?;
    found.cases.extend(kept(root, class)?);
    Ok(found)
}

/// [`checked`], and a case that fits its class: a prompt-injection case is
/// one a writer's text keeps as data, and only it.
pub fn checked_in(class: &str, case: &Case) -> Result<(), String> {
    checked(case)?;
    let id = &case.id;
    match (
        class == PROMPT_INJECTION,
        case.want == "data",
        case.from.as_deref(),
    ) {
        (true, true, Some(from)) if SOURCES.contains(&from) => {
            if markers(&case.input).is_empty() {
                return Err(format!(
                    "{id}: a prompt-injection text holds words a builder keeps: {MARKER} characters or more, two words or more"
                ));
            }
            Ok(())
        }
        (true, ..) => Err(format!(
            "{id}: a prompt-injection case wants data, from {}",
            SOURCES.join(", ")
        )),
        (false, false, None) => Ok(()),
        (false, ..) => Err(format!(
            "{id}: only a prompt-injection case wants data or says from"
        )),
    }
}

/// Whether a case is one devflow runs: a plain id, a known want, a bounded
/// input, and nothing in it that names a real host or person.
pub fn checked(case: &Case) -> Result<(), String> {
    let id = &case.id;
    if id.is_empty()
        || id.len() > 60
        || !id
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    {
        return Err(format!(
            "`{id}` is not a case id: lowercase letters, digits and -"
        ));
    }
    if !WANTS.contains(&case.want.as_str()) {
        return Err(format!("{id}: want is one of {}", WANTS.join(", ")));
    }
    let then = case.then.as_deref().unwrap_or_default();
    if case.input.is_empty() || case.input.len() + then.len() > MOST_INPUT {
        return Err(format!("{id}: an input is 1 to {MOST_INPUT} bytes"));
    }
    if case
        .times
        .is_some_and(|times| times == 0 || times > MOST_TIMES)
    {
        return Err(format!("{id}: times is 1 to {MOST_TIMES}"));
    }
    neutral(&case.input)
        .and_then(|()| neutral(then))
        .map_err(|why| format!("{id}: {why}"))
}

/// The top-level names a host is said under, besides every two-letter
/// country's: a word ending in one names a real place, or an inside one.
const PUBLIC: [&str; 40] = [
    "com", "net", "org", "io", "dev", "app", "ai", "cloud", "info", "biz", "tech", "site",
    "online", "xyz", "gov", "edu", "mil", "int", "arpa", "internal", "local", "corp", "lan",
    "home", "intranet", "store", "shop", "live", "blog", "news", "page", "link", "top", "pro",
    "name", "mobi", "asia", "jobs", "travel", "global",
];

/// The XML namespaces a document declares without fetching them.
const NAMESPACES: [&str; 1] = ["http://www.w3.org/2001/XInclude"];

/// A source or data file's two-letter extension, read as one before a
/// country's only in a path: `src/main.rs`, never a bare `main.rs`.
const FILE_LABELS: [&str; 14] = [
    "rs", "py", "go", "js", "ts", "sh", "md", "rb", "pl", "cs", "kt", "id", "db", "so",
];

/// `text` without the namespaces it declares (`xmlns:xi="…"`): a namespace
/// named anywhere else is a URL like any other.
fn without_declared_namespaces(text: &str) -> String {
    let mut kept = String::with_capacity(text.len());
    let mut rest = text;
    while let Some((at, namespace)) = NAMESPACES
        .iter()
        .filter_map(|namespace| rest.find(namespace).map(|at| (at, *namespace)))
        .min()
    {
        let before = &rest[..at];
        let declared = before
            .strip_suffix(['"', '\''])
            .map(|before| before.trim_end().strip_suffix('=').unwrap_or("x"))
            .map(str::trim_end)
            .is_some_and(|attribute| {
                let name = attribute
                    .rsplit(|ch: char| ch.is_whitespace() || ch == '<')
                    .next()
                    .unwrap_or_default();
                name == "xmlns"
                    || name
                        .strip_prefix("xmlns:")
                        .is_some_and(|prefix| !prefix.is_empty())
            });
        kept.push_str(before);
        if !declared {
            kept.push_str(namespace);
        }
        rest = &rest[at + namespace.len()..];
    }
    kept.push_str(rest);
    kept
}

/// Names that are no one's: RFC 2606 and 6761.
fn reserved_name(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host.is_empty()
        || host == "localhost"
        || ["example.com", "example.net", "example.org"].contains(&host.as_str())
        || [
            ".localhost",
            ".example",
            ".test",
            ".invalid",
            ".example.com",
        ]
        .iter()
        .any(|end| host.ends_with(end))
}

/// An IPv4 address as `inet_aton` reads it: one to four parts, each
/// decimal, `0x` hex or `0` octal (`2130706433`, `0x7f000001`, `127.1`).
fn aton(host: &str) -> Option<Ipv4Addr> {
    let parts: Vec<u64> = host
        .split('.')
        .map(|part| {
            if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).ok()
            } else if part.len() > 1 && part.starts_with('0') {
                u64::from_str_radix(&part[1..], 8).ok()
            } else {
                part.parse().ok()
            }
        })
        .collect::<Option<_>>()?;
    let (last, head) = parts.split_last()?;
    if head.len() > 3 || head.iter().any(|part| *part > 255) {
        return None;
    }
    let room = 8 * (4 - head.len() as u32);
    if *last >= 1u64 << room {
        return None;
    }
    let value = head
        .iter()
        .enumerate()
        .fold(*last, |sum, (at, part)| sum | part << (24 - 8 * at as u32));
    u32::try_from(value).ok().map(Ipv4Addr::from)
}

/// An address that leads inside, and never a cloud's metadata address:
/// link-local only in its first /24, far from 169.254.169.254 and
/// 169.254.170.2.
fn inside_v4(ip: Ipv4Addr) -> bool {
    let [first, second, third, _] = ip.octets();
    if first == 169 && second == 254 {
        return third == 0;
    }
    ip.is_loopback() || ip.is_unspecified() || ip.is_private()
}

fn inside_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return inside_v4(v4);
    }
    // A cloud's IPv6 metadata address sits in the private range.
    if ip == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254) {
        return false;
    }
    let first = ip.segments()[0];
    ip.is_loopback()
        || ip.is_unspecified()
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
}

/// A name that resolves nowhere: `.test`, `.invalid`, `.example`.
fn nowhere(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    ["test", "invalid", "example"]
        .iter()
        .any(|end| host == *end || host.ends_with(&format!(".{end}")))
}

/// An address that leads inside, said in any spelling: dotted, decimal,
/// hex or octal IPv4, an IPv6 literal, or a loopback name.
fn inside_address(host: &str) -> Option<bool> {
    let host = host.trim_end_matches('.');
    if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return Some(inner.parse::<Ipv6Addr>().is_ok_and(inside_v6));
    }
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        return Some(true);
    }
    aton(host).map(inside_v4)
}

/// Whether a URL's host and port are ones a case may name: none (a
/// `file:///` path), a name that resolves nowhere, or an inside address on
/// port 1, where nothing listens.
fn url_host(host: &str, port: Option<&str>) -> Result<(), String> {
    if host.is_empty() || nowhere(host) {
        return Ok(());
    }
    match inside_address(host) {
        Some(true) if port == Some("1") => Ok(()),
        Some(true) => Err(format!(
            "`{host}` is named on a port that may listen: use port 1"
        )),
        _ => Err(format!(
            "`{host}` is a host someone may own: use loopback on port 1, or a .test name"
        )),
    }
}

/// Each URL in `text`, however its slashes are written (`http:/`, `http:\\`,
/// `HTTP://`): its host, port and userinfo.
fn urls(text: &str) -> Vec<(String, Option<String>, Option<String>)> {
    let mut found = Vec::new();
    let bytes = text.as_bytes();
    for (colon, _) in text.match_indices(':') {
        let scheme_start = text[..colon]
            .rfind(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-')))
            .map_or(0, |at| at + 1);
        let scheme = &text[scheme_start..colon];
        if scheme.len() < 2 || !scheme.starts_with(|ch: char| ch.is_ascii_alphabetic()) {
            continue;
        }
        let after = &text[colon + 1..];
        if !after.starts_with(['/', '\\']) {
            continue;
        }
        let start = if scheme.eq_ignore_ascii_case("file") {
            // `file:///path` names no host; `file://host/path` does.
            match after.strip_prefix("//") {
                Some(rest) if !rest.starts_with(['/', '\\']) => colon + 3,
                _ => continue,
            }
        } else {
            let slashes = after.len() - after.trim_start_matches(['/', '\\']).len();
            colon + 1 + slashes
        };
        let end = text[start..]
            .find(|ch: char| {
                ch.is_whitespace()
                    || matches!(
                        ch,
                        '/' | '\\'
                            | '?'
                            | '#'
                            | '"'
                            | '\''
                            | '<'
                            | '>'
                            | '('
                            | ')'
                            | ','
                            | ';'
                            | '`'
                    )
            })
            .map_or(bytes.len(), |at| start + at);
        let authority = &text[start..end];
        let (who, rest) = match authority.rsplit_once('@') {
            Some((who, rest)) => (Some(who.to_owned()), rest),
            None => (None, authority),
        };
        let (host, port) = if rest.starts_with('[') {
            match rest.find(']') {
                Some(close) => (&rest[..=close], rest[close + 1..].strip_prefix(':')),
                None => (rest, None),
            }
        } else {
            match rest.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (rest, None),
            }
        };
        found.push((host.to_owned(), port.map(str::to_owned), who));
    }
    found
}

/// A token that is an address, though no URL names it: four dotted parts
/// (in any base) or an IPv6 literal.
fn bare_address(token: &str) -> Option<bool> {
    if token.contains(':') {
        if let Ok(ip) = token.parse::<Ipv6Addr>() {
            return Some(inside_v6(ip));
        }
    }
    for part in token.split(':') {
        let pieces: Vec<&str> = part.split('.').collect();
        let numeric = pieces.len() == 4
            && pieces.iter().all(|piece| {
                !piece.is_empty()
                    && (piece.chars().all(|ch| ch.is_ascii_digit())
                        || piece
                            .strip_prefix("0x")
                            .is_some_and(|hex| hex.chars().all(|ch| ch.is_ascii_hexdigit())))
            });
        if numeric {
            return Some(aton(part).is_some_and(inside_v4));
        }
    }
    None
}

/// Every host and address in `text` is one nobody owns: a URL's host is
/// loopback or private on port 1, or a name that resolves nowhere; a bare
/// address leads inside; no name or e-mail address ends in a real place.
pub fn neutral(text: &str) -> Result<(), String> {
    let text = without_declared_namespaces(text);
    for (host, port, who) in urls(&text) {
        url_host(&host, port.as_deref())?;
        if let Some(who) = who.filter(|who| who.contains('.')) {
            if !reserved_name(&who) {
                return Err(format!("`{who}` names a real host"));
            }
        }
    }
    let tokens = text.split(|ch: char| {
        ch.is_whitespace()
            || matches!(
                ch,
                '/' | '\\'
                    | '"'
                    | '\''
                    | '<'
                    | '>'
                    | '('
                    | ')'
                    | ','
                    | ';'
                    | '='
                    | '&'
                    | '?'
                    | '#'
                    | '@'
                    | '['
                    | ']'
                    | '`'
            )
    });
    for token in tokens.filter(|token| !token.is_empty()) {
        if bare_address(token) == Some(false) {
            return Err(format!("`{token}` is an address someone may own"));
        }
        // `127.0.0.1:6379`, `localhost:6379`: an inside address on a port
        // that may listen.
        let parts: Vec<&str> = token.split(':').collect();
        for pair in parts.windows(2) {
            let port = pair[1];
            let numbered = !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit());
            if numbered && port != "1" && inside_address(pair[0]) == Some(true) {
                return Err(format!(
                    "`{token}` names a port that may listen: use port 1"
                ));
            }
        }
    }
    // Each word with where it starts, so a file in a path is told from a host.
    let mut words: Vec<(usize, &str)> = Vec::new();
    let mut start = None;
    for (at, ch) in text.char_indices().chain([(text.len(), ' ')]) {
        let kept = ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '@');
        match (kept, start) {
            (true, None) => start = Some(at),
            (false, Some(from)) => {
                words.push((from, &text[from..at]));
                start = None;
            }
            _ => {}
        }
    }
    for (from, word) in words {
        let before = &text[..from];
        let in_path = (before.ends_with('/') || before.ends_with('\\'))
            && !before.ends_with("//")
            && !before.ends_with(":/");
        let (who, place) = match word.split_once('@') {
            Some((who, place)) => (Some(who), place),
            None => (None, word),
        };
        let place = place.trim_end_matches('.');
        if !place.contains('.') || reserved_name(place) || nowhere(place) {
            continue;
        }
        if who.is_some_and(|who| !who.is_empty()) && inside_address(place) != Some(true) {
            return Err(format!("`{word}` is an address someone may own"));
        }
        let last = place
            .rsplit('.')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let file =
            in_path && place.matches('.').count() == 1 && FILE_LABELS.contains(&last.as_str());
        let country = !file && last.len() == 2 && last.chars().all(|ch| ch.is_ascii_alphabetic());
        if country || PUBLIC.contains(&last.as_str()) {
            return Err(format!("`{place}` names a real host"));
        }
    }
    Ok(())
}

/// A test runner a table is written for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runner {
    Jest,
    Vitest,
    Go,
    Pytest,
}

impl Runner {
    pub const ALL: [Runner; 4] = [Runner::Jest, Runner::Vitest, Runner::Go, Runner::Pytest];

    pub fn word(self) -> &'static str {
        match self {
            Runner::Jest => "jest",
            Runner::Vitest => "vitest",
            Runner::Go => "go",
            Runner::Pytest => "pytest",
        }
    }

    pub fn of(word: &str) -> Option<Runner> {
        Runner::ALL.into_iter().find(|one| one.word() == word)
    }
}

fn quoted(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_default()
}

/// A case's input as the runner's language writes it.
fn literal(case: &Case, runner: Runner) -> String {
    let base = quoted(&case.input);
    let mut said = match (case.times, runner) {
        (None, _) => base,
        (Some(times), Runner::Go) => format!("strings.Repeat({base}, {times})"),
        (Some(times), Runner::Pytest) => format!("{base} * {times}"),
        (Some(times), _) => format!("{base}.repeat({times})"),
    };
    if let Some(then) = case.then.as_deref().filter(|then| !then.is_empty()) {
        said = format!("{said} + {}", quoted(then));
    }
    said
}

/// A class's name as a type's (`PromptInjection`) or a function's
/// (`prompt_injection`).
fn title(name: &str) -> String {
    name.split(['-', '_'])
        .map(|part| {
            let mut chars = part.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_ascii_uppercase().to_string() + chars.as_str()
            })
        })
        .collect()
}

fn snake(name: &str) -> String {
    name.replace('-', "_")
}

/// A test table for `runner`: every case of `class`, with a `check` the
/// project fills in; a prompt-injection table over a message builder.
pub fn table(class: &Class, runner: Runner) -> String {
    if class.class == PROMPT_INJECTION {
        return builder_table(class, runner);
    }
    let within = class.within_ms.unwrap_or(WITHIN_MS);
    let name = &class.class;
    let head = format!(
        "devflow payloads: {name}, {} cases. {}\nFill in check(): give the input to the code under test and say what it did:\n\"rejected\" (refused it) or \"inert\" (took it as plain data). A \"fast\" case\nonly has to answer within {within} ms.",
        class.cases.len(),
        class.about
    );
    let comment = |mark: &str| {
        head.lines()
            .map(|line| format!("{mark} {line}\n"))
            .collect::<String>()
    };
    let rows = |indent: &str, open: &str, close: &str| {
        class
            .cases
            .iter()
            .map(|case| {
                format!(
                    "{indent}{open}{}, {}, {}{close},\n",
                    quoted(&case.id),
                    literal(case, runner),
                    quoted(&case.want)
                )
            })
            .collect::<String>()
    };
    match runner {
        Runner::Jest | Runner::Vitest => {
            let import = if runner == Runner::Vitest {
                "import { describe, test, expect } from \"vitest\";\n\n"
            } else {
                ""
            };
            format!(
                "{}{import}async function check(input) {{\n  throw new Error(\"devflow payloads: fill in check() for {name}\");\n}}\n\nconst cases = [\n{}];\n\ndescribe(\"payloads: {name}\", () => {{\n  test.each(cases)(\"%s\", async (id, input, want) => {{\n    const started = Date.now();\n    const got = await check(input);\n    if (want === \"fast\") {{\n      expect(Date.now() - started).toBeLessThan({within});\n    }} else {{\n      expect(got).toBe(want);\n    }}\n  }});\n}});\n",
                comment("//"),
                rows("  ", "[", "]")
            )
        }
        Runner::Go => {
            let title = title(name);
            format!(
                "{}package payloads_test\n\nimport (\n\t\"strings\"\n\t\"testing\"\n\t\"time\"\n)\n\nvar _ = strings.Repeat\n\nfunc check{title}(input string) string {{\n\tpanic(\"devflow payloads: fill in check{title}() for {name}\")\n}}\n\nfunc TestPayloads{title}(t *testing.T) {{\n\tcases := []struct{{ id, input, want string }}{{\n{}\t}}\n\tfor _, c := range cases {{\n\t\tt.Run(c.id, func(t *testing.T) {{\n\t\t\tstarted := time.Now()\n\t\t\tgot := check{title}(c.input)\n\t\t\tif c.want == \"fast\" {{\n\t\t\t\tif took := time.Since(started); took > {within}*time.Millisecond {{\n\t\t\t\t\tt.Fatalf(\"took %v\", took)\n\t\t\t\t}}\n\t\t\t}} else if got != c.want {{\n\t\t\t\tt.Fatalf(\"got %q, want %q\", got, c.want)\n\t\t\t}}\n\t\t}})\n\t}}\n}}\n",
                comment("//"),
                rows("\t\t", "{", "}")
            )
        }
        Runner::Pytest => format!(
            "{}import time\n\nimport pytest\n\n\ndef check(input):\n    raise NotImplementedError(\"devflow payloads: fill in check() for {name}\")\n\n\nCASES = [\n{}]\n\n\n@pytest.mark.parametrize(\"case_id,given,want\", CASES, ids=[case[0] for case in CASES])\ndef test_payloads_{snake}(case_id, given, want):\n    started = time.monotonic()\n    got = check(given)\n    if want == \"fast\":\n        assert time.monotonic() - started < {within} / 1000\n    else:\n        assert got == want\n",
            comment("#"),
            rows("    ", "(", ")"),
            snake = snake(name)
        ),
    }
}

/// The fewest characters a marker has.
const MARKER: usize = 12;

/// A case's markers: each run of letters, digits and spaces in its text of
/// at least [`MARKER`] characters and two words. A builder that escapes a
/// delimiter or a quote still keeps them, and each is followed, so a role
/// lifted from any marker is seen; a shorter or one-word fragment is not
/// followed. A marker the builder says on its own is its, not the case's.
pub fn markers(input: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for part in input.split(|ch: char| !(ch.is_alphanumeric() || ch == ' ')) {
        let part = part.trim();
        if part.len() >= MARKER && part.contains(' ') && !found.iter().any(|had| had == part) {
            found.push(part.to_owned());
        }
    }
    found
}

/// The prompt-injection table: each case's text given to the project's
/// message builder as its writer's, and the messages it builds checked for
/// where each of its markers landed. No model is called. It checks that no
/// writer's text becomes a system, developer or assistant message, and that
/// a tool's stays in its tool role; whether a write tool asks first is the
/// review's.
fn builder_table(class: &Class, runner: Runner) -> String {
    let name = &class.class;
    let head = format!(
        "devflow payloads: {name}, {} cases. {}\nFill in build(): give the text to the code that builds a model's messages, as\nif `from` (a user, a tool or a document) wrote it, and return the messages it\nbuilds, each with its role and content. No model is called.",
        class.cases.len(),
        class.about
    );
    let comment = |mark: &str| {
        head.lines()
            .map(|line| format!("{mark} {line}\n"))
            .collect::<String>()
    };
    let rows = |indent: &str, open: &str, close: &str| {
        class
            .cases
            .iter()
            .map(|case| {
                let listed = markers(&case.input)
                    .iter()
                    .map(|marker| quoted(marker))
                    .collect::<Vec<_>>()
                    .join(", ");
                let list = match runner {
                    Runner::Go => format!("[]string{{{listed}}}"),
                    _ => format!("[{listed}]"),
                };
                format!(
                    "{indent}{open}{}, {}, {}, {list}{close},\n",
                    quoted(&case.id),
                    literal(case, runner),
                    quoted(case.from.as_deref().unwrap_or("user"))
                )
            })
            .collect::<String>()
    };
    let title = title(name);
    let snake = snake(name);
    match runner {
        Runner::Jest | Runner::Vitest => {
            let import = if runner == Runner::Vitest {
                "import { describe, test } from \"vitest\";\n\n"
            } else {
                ""
            };
            format!(
                "{}{import}async function build(content, from) {{\n  throw new Error(\"devflow payloads: fill in build() for {name}\");\n}}\n\nconst cases = [\n{rows}];\n\n// The case's markers a message holds: words a builder that escapes a\n// delimiter still keeps, read as JSON so a list of blocks reads too.\nfunction held(message, markers) {{\n  const said = JSON.stringify(message.content ?? \"\");\n  return markers.filter((marker) => said.includes(marker));\n}}\n\n// A tool's text in its tool role, or only inside tool_result blocks.\nfunction inToolRole(message, markers) {{\n  if (message.role === \"tool\") return true;\n  if (!Array.isArray(message.content)) return false;\n  return message.content.every(\n    (block) => block.type === \"tool_result\" || !markers.some((marker) => JSON.stringify(block).includes(marker)),\n  );\n}}\n\ndescribe(\"payloads: {name}\", () => {{\n  test.each(cases)(\"%s\", async (id, input, from, listed) => {{\n    // A marker the builder says on its own is its, not the case's.\n    const own = JSON.stringify(await build(\"x\", from));\n    const markers = listed.filter((marker) => !own.includes(marker));\n    if (markers.length === 0) {{\n      throw new Error(\"every marker of the case is in the builder's own messages\");\n    }}\n    const holding = (await build(input, from)).filter((message) => held(message, markers).length > 0);\n    if (holding.length === 0) {{\n      throw new Error(`the ${{from}} content is in no message`);\n    }}\n    for (const message of holding) {{\n      if (message.role === \"system\" || message.role === \"developer\") {{\n        throw new Error(`${{from}} content became a ${{message.role}} message`);\n      }}\n      if (message.role === \"assistant\") {{\n        throw new Error(`${{from}} content became the assistant's message`);\n      }}\n      if (from === \"tool\" && !inToolRole(message, held(message, markers))) {{\n        throw new Error(\"tool output reached the model outside its tool role\");\n      }}\n    }}\n  }});\n}});\n",
                comment("//"),
                rows = rows("  ", "[", "]")
            )
        }
        Runner::Go => format!(
            "{}package payloads_test\n\nimport (\n\t\"strings\"\n\t\"testing\"\n)\n\n// A message as the builder hands it to a model; a tool_result block is\n// returned as Role \"tool\".\ntype message{title} struct{{ Role, Content string }}\n\nfunc build{title}(content, from string) []message{title} {{\n\tpanic(\"devflow payloads: fill in build{title}() for {name}\")\n}}\n\nfunc TestPayloads{title}(t *testing.T) {{\n\tcases := []struct {{\n\t\tid, input, from string\n\t\tmarkers         []string\n\t}}{{\n{rows}\t}}\n\tfor _, c := range cases {{\n\t\tt.Run(c.id, func(t *testing.T) {{\n\t\t\t// A marker the builder says on its own is its, not the case's.\n\t\t\town := \"\"\n\t\t\tfor _, m := range build{title}(\"x\", c.from) {{\n\t\t\t\town += m.Content + \"\\n\"\n\t\t\t}}\n\t\t\tvar markers []string\n\t\t\tfor _, marker := range c.markers {{\n\t\t\t\tif !strings.Contains(own, marker) {{\n\t\t\t\t\tmarkers = append(markers, marker)\n\t\t\t\t}}\n\t\t\t}}\n\t\t\tif len(markers) == 0 {{\n\t\t\t\tt.Fatalf(\"every marker of the case is in the builder's own messages\")\n\t\t\t}}\n\t\t\theld := 0\n\t\t\tfor _, m := range build{title}(c.input, c.from) {{\n\t\t\t\tholds := false\n\t\t\t\tfor _, marker := range markers {{\n\t\t\t\t\tholds = holds || strings.Contains(m.Content, marker)\n\t\t\t\t}}\n\t\t\t\tif !holds {{\n\t\t\t\t\tcontinue\n\t\t\t\t}}\n\t\t\t\theld++\n\t\t\t\tswitch m.Role {{\n\t\t\t\tcase \"system\", \"developer\":\n\t\t\t\t\tt.Fatalf(\"%s content became a %s message\", c.from, m.Role)\n\t\t\t\tcase \"assistant\":\n\t\t\t\t\tt.Fatalf(\"%s content became the assistant's message\", c.from)\n\t\t\t\t}}\n\t\t\t\tif c.from == \"tool\" && m.Role != \"tool\" {{\n\t\t\t\t\tt.Fatalf(\"tool output reached the model outside its tool role\")\n\t\t\t\t}}\n\t\t\t}}\n\t\t\tif held == 0 {{\n\t\t\t\tt.Fatalf(\"the %s content is in no message\", c.from)\n\t\t\t}}\n\t\t}})\n\t}}\n}}\n",
            comment("//"),
            rows = rows("\t\t", "{", "}")
        ),
        Runner::Pytest => format!(
            "{}import json\n\nimport pytest\n\n\ndef build(content, source):\n    raise NotImplementedError(\"devflow payloads: fill in build() for {name}\")\n\n\nCASES = [\n{rows}]\n\n\ndef held(message, markers):\n    \"\"\"The case's markers a message holds: words a builder that escapes a delimiter still keeps.\"\"\"\n    said = json.dumps(message.get(\"content\", \"\"), ensure_ascii=False)\n    return [marker for marker in markers if marker in said]\n\n\ndef in_tool_role(message, markers):\n    \"\"\"A tool's text in its tool role, or only inside tool_result blocks.\"\"\"\n    if message[\"role\"] == \"tool\":\n        return True\n    content = message.get(\"content\", \"\")\n    if not isinstance(content, list):\n        return False\n    return all(\n        block.get(\"type\") == \"tool_result\" or not any(marker in json.dumps(block, ensure_ascii=False) for marker in markers)\n        for block in content\n    )\n\n\n@pytest.mark.parametrize(\"case_id,given,source,markers\", CASES, ids=[case[0] for case in CASES])\ndef test_payloads_{snake}(case_id, given, source, markers):\n    own = json.dumps(build(\"x\", source), ensure_ascii=False)\n    markers = [marker for marker in markers if marker not in own]  # the builder's own words\n    assert markers, \"every marker of the case is in the builder's own messages\"\n    holding = [message for message in build(given, source) if held(message, markers)]\n    assert holding, f\"the {{source}} content is in no message\"\n    for message in holding:\n        role = message[\"role\"]\n        assert role not in (\"system\", \"developer\"), f\"{{source}} content became a {{role}} message\"\n        assert role != \"assistant\", f\"{{source}} content became the assistant's message\"\n        if source == \"tool\":\n            assert in_tool_role(message, held(message, markers)), \"tool output reached the model outside its tool role\"\n",
            comment("#"),
            rows = rows("    ", "(", ")")
        ),
    }
}

/// The regression classes' cases, for the attack's prompt.
pub fn regression_section(root: &Path, classes: &[String]) -> Result<String, String> {
    let mut out = String::new();
    for name in classes {
        let found = class(root, name)?;
        out.push_str(&format!("### {name}: {}\n", found.about));
        for case in &found.cases {
            out.push_str(&serde_json::to_string(case).unwrap_or_default());
            out.push('\n');
        }
    }
    Ok(out)
}

/// The schemes a URL parser reads a host after, with slashes or without.
const SPECIAL: [&str; 6] = ["http", "https", "ws", "wss", "ftp", "file"];

/// Whether `text` holds no host syntax at all: no URL, no `@`, no `::`, no
/// `name:port`, no dotted, long or hex number. The rule for a case an
/// attacker proposes, which a parser could otherwise read a host from in a
/// spelling no check foresees; the shipped cases and a person's own file are
/// held to [`neutral`] instead.
pub fn host_free(text: &str) -> Result<(), String> {
    let lower: String = text
        .chars()
        .filter(|ch| !matches!(ch, '\t' | '\n' | '\r'))
        .collect::<String>()
        .to_ascii_lowercase();
    if lower.contains('@') {
        return Err("it names someone at a host (`@`)".to_owned());
    }
    if lower.contains("::") {
        return Err("it holds an IPv6 address (`::`)".to_owned());
    }
    for (colon, _) in lower.match_indices(':') {
        let start = lower[..colon]
            .rfind(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-')))
            .map_or(0, |at| at + 1);
        let before = &lower[start..colon];
        let after = &lower[colon + 1..];
        if SPECIAL.contains(&before) || (!before.is_empty() && after.starts_with(['/', '\\'])) {
            return Err(format!("it holds a URL (`{before}:`)"));
        }
        if !before.is_empty() && after.starts_with(|ch: char| ch.is_ascii_digit()) {
            return Err(format!("it names a port (`{before}:`)"));
        }
    }
    for token in lower.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '.')) {
        let number = |part: &str| {
            part.starts_with(|ch: char| ch.is_ascii_digit())
                && part.chars().all(|ch| ch.is_ascii_hexdigit() || ch == 'x')
        };
        let parts: Vec<&str> = token.split('.').filter(|part| !part.is_empty()).collect();
        if token.contains('.') && parts.len() >= 2 && parts.iter().all(|part| number(part)) {
            return Err(format!("it holds a dotted number (`{token}`)"));
        }
        let digits = token.chars().all(|ch| ch.is_ascii_digit());
        if (digits && token.len() >= 8) || (token.starts_with("0x") && token.len() >= 8) {
            return Err(format!(
                "it holds a number an address may be read from (`{token}`)"
            ));
        }
    }
    Ok(())
}

/// The cases an attacker's answer proposes, numbered `c1`, `c2`, and the
/// ones left out with why: each is held to [`checked`] and [`host_free`].
pub fn proposed_of(answer: &Value) -> (Vec<Value>, Vec<Value>) {
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    for one in answer["cases"].as_array().into_iter().flatten() {
        if kept.len() + dropped.len() == MOST_PROPOSED {
            break;
        }
        let text = |key: &str| one[key].as_str().unwrap_or_default().to_owned();
        let class = text("class");
        let from = text("from");
        let case = Case {
            id: format!("c{}", kept.len() + 1),
            input: text("input"),
            times: None,
            then: None,
            from: (!from.is_empty()).then_some(from),
            want: text("want"),
        };
        let held = shipped(&class)
            .and_then(|_| checked_in(&class, &case))
            .and_then(|()| host_free(&case.input));
        match held {
            Ok(()) => {
                let why: String = text("why")
                    .chars()
                    .filter(|ch| !ch.is_control())
                    .take(400)
                    .collect();
                let mut one = json!({ "id": case.id, "class": class, "input": case.input,
                                      "want": case.want, "why": why });
                if let Some(from) = &case.from {
                    one["from"] = json!(from);
                }
                kept.push(one);
            }
            Err(reason) => dropped.push(json!({ "class": class, "reason": reason })),
        }
    }
    (kept, dropped)
}

/// Keeps a proposed case in the project's own cases of its class, under an
/// id of its own; a person's yes on a terminal comes first, and is asked by
/// whoever calls this.
pub fn keep(root: &Path, proposed: &Value) -> Result<String, String> {
    let class = proposed["class"].as_str().unwrap_or_default();
    let shipped_cases = shipped(class)?.cases;
    let mut cases = kept(root, class)?;
    let input = proposed["input"].as_str().unwrap_or_default().to_owned();
    if shipped_cases
        .iter()
        .chain(&cases)
        .any(|case| case.input == input)
    {
        return Err(format!("{class} has this input already"));
    }
    if cases.len() >= MOST_KEPT {
        return Err(format!(
            "{class} keeps at most {MOST_KEPT} cases of a project's own"
        ));
    }
    let mut number = cases.len() + 1;
    let id = loop {
        let id = format!("kept-{number}");
        if !shipped_cases.iter().chain(&cases).any(|case| case.id == id) {
            break id;
        }
        number += 1;
    };
    let case = Case {
        id,
        input,
        times: None,
        then: None,
        from: proposed["from"].as_str().map(str::to_owned),
        want: proposed["want"].as_str().unwrap_or_default().to_owned(),
    };
    checked_in(class, &case)?;
    host_free(&case.input)?;
    cases.push(case);
    let relative = kept_path(root, class);
    let text = serde_json::to_string_pretty(&cases).unwrap_or_default() + "\n";
    crate::attack::put(root, &relative, &text)?;
    Ok(relative)
}

#[cfg(test)]
#[path = "payloads_tests.rs"]
mod tests;
