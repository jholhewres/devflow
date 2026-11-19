//! A generic repertoire of attack inputs by class: each case a neutral
//! input and what safe code does with it, made into a test table a project
//! fills in. A project keeps its own cases beside it, in devflow's folder,
//! and only from a person on a terminal (`devflow payloads add`).
//!
//! Neutral: a case names no real host, address or person. Its hosts are
//! loopback, private, link-local or reserved names, never a cloud's
//! metadata address, so a table run on any machine reaches nothing.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Each class devflow ships, and its cases.
pub const SHIPPED: [(&str, &str); 7] = [
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
];

/// What safe code does with a case: refuses it, takes it as plain data, or
/// answers within the class's time.
pub const WANTS: [&str; 3] = ["rejected", "inert", "fast"];
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
        checked(case).map_err(|why| format!("{relative}: {why}"))?;
    }
    Ok(cases)
}

/// The class with the project's kept cases after devflow's.
pub fn class(root: &Path, class: &str) -> Result<Class, String> {
    let mut found = shipped(class)?;
    found.cases.extend(kept(root, class)?);
    Ok(found)
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

/// The top-level names a public host is said under: a word ending in one
/// names a real place.
const PUBLIC: [&str; 24] = [
    "com", "net", "org", "io", "br", "dev", "app", "co", "ai", "cloud", "info", "biz", "us", "uk",
    "de", "me", "tech", "site", "online", "xyz", "gov", "edu", "mil", "int",
];

/// Names that are no one's: RFC 2606 and 6761, and the XML namespace a
/// document names without fetching it.
fn reserved_name(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host.is_empty()
        || host == "localhost"
        || ["example.com", "example.net", "example.org", "www.w3.org"].contains(&host.as_str())
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

/// An address that leads inside, and never a cloud's metadata address.
fn inside_v4(ip: Ipv4Addr) -> bool {
    ip != Ipv4Addr::new(169, 254, 169, 254)
        && (ip.is_loopback() || ip.is_unspecified() || ip.is_private() || ip.is_link_local())
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

/// Whether a URL's host is one a case may name.
fn reserved_host(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return inner.parse::<Ipv6Addr>().is_ok_and(inside_v6);
    }
    match aton(host) {
        Some(ip) => inside_v4(ip),
        None => reserved_name(host),
    }
}

/// Every host a URL in `text` names, and every address and public-looking
/// name in it, is one nobody owns.
pub fn neutral(text: &str) -> Result<(), String> {
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        let after = &rest[at + 3..];
        let end = after
            .find(['/', '?', '#', '"', '\'', ' ', '<', '>'])
            .unwrap_or(after.len());
        let authority = &after[..end];
        let (who, host) = match authority.rsplit_once('@') {
            Some((who, host)) => (Some(who), host),
            None => (None, authority),
        };
        let host = match host.rfind(':') {
            Some(colon)
                if !host.ends_with(']')
                    && host[colon + 1..].chars().all(|ch| ch.is_ascii_digit()) =>
            {
                &host[..colon]
            }
            _ => host,
        };
        if !reserved_host(host) {
            return Err(format!(
                "`{host}` is a host someone may own: use loopback or a reserved name"
            ));
        }
        if let Some(who) = who.filter(|who| who.contains('.')) {
            if !reserved_name(who) {
                return Err(format!("`{who}` names a real host"));
            }
        }
        rest = &after[end..];
    }
    let words =
        text.split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '@')));
    for word in words.filter(|word| !word.is_empty()) {
        let (who, place) = match word.split_once('@') {
            Some((who, place)) => (Some(who), place),
            None => (None, word),
        };
        if who.is_some_and(|who| !who.is_empty()) && place.contains('.') && !reserved_host(place) {
            return Err(format!("`{word}` is an address someone may own"));
        }
        let last = place
            .rsplit('.')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if place.contains('.') && PUBLIC.contains(&last.as_str()) && !reserved_name(place) {
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

/// A test table for `runner`: every case of `class`, with a `check` the
/// project fills in.
pub fn table(class: &Class, runner: Runner) -> String {
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
    let rows = |open: &str, close: &str| {
        class
            .cases
            .iter()
            .map(|case| {
                format!(
                    "  {open}{}, {}, {}{close},\n",
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
                rows("[", "]")
            )
        }
        Runner::Go => {
            let title: String = name
                .chars()
                .enumerate()
                .map(|(at, ch)| if at == 0 { ch.to_ascii_uppercase() } else { ch })
                .collect();
            format!(
                "{}package payloads_test\n\nimport (\n\t\"strings\"\n\t\"testing\"\n\t\"time\"\n)\n\nvar _ = strings.Repeat\n\nfunc check{title}(input string) string {{\n\tpanic(\"devflow payloads: fill in check{title}() for {name}\")\n}}\n\nfunc TestPayloads{title}(t *testing.T) {{\n\tcases := []struct{{ id, input, want string }}{{\n{}\t}}\n\tfor _, c := range cases {{\n\t\tt.Run(c.id, func(t *testing.T) {{\n\t\t\tstarted := time.Now()\n\t\t\tgot := check{title}(c.input)\n\t\t\tif c.want == \"fast\" {{\n\t\t\t\tif took := time.Since(started); took > {within}*time.Millisecond {{\n\t\t\t\t\tt.Fatalf(\"took %v\", took)\n\t\t\t\t}}\n\t\t\t}} else if got != c.want {{\n\t\t\t\tt.Fatalf(\"got %q, want %q\", got, c.want)\n\t\t\t}}\n\t\t}})\n\t}}\n}}\n",
                comment("//"),
                rows("\t{", "}").replace("  \t{", "\t\t{")
            )
        }
        Runner::Pytest => format!(
            "{}import time\n\nimport pytest\n\n\ndef check(input):\n    raise NotImplementedError(\"devflow payloads: fill in check() for {name}\")\n\n\nCASES = [\n{}]\n\n\n@pytest.mark.parametrize(\"case_id,given,want\", CASES, ids=[case[0] for case in CASES])\ndef test_payloads_{name}(case_id, given, want):\n    started = time.monotonic()\n    got = check(given)\n    if want == \"fast\":\n        assert time.monotonic() - started < {within} / 1000\n    else:\n        assert got == want\n",
            comment("#"),
            rows("(", ")").replace("  (", "    (")
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

/// The cases an attacker's answer proposes, each checked as a kept one is
/// and numbered `c1`, `c2`; one that is not neutral is left out.
pub fn proposed_of(answer: &Value) -> Vec<Value> {
    let mut kept = Vec::new();
    for one in answer["cases"].as_array().into_iter().flatten() {
        if kept.len() == MOST_PROPOSED {
            break;
        }
        let text = |key: &str| one[key].as_str().unwrap_or_default().to_owned();
        let class = text("class");
        if shipped(&class).is_err() {
            continue;
        }
        let case = Case {
            id: format!("c{}", kept.len() + 1),
            input: text("input"),
            times: None,
            then: None,
            want: text("want"),
        };
        if checked(&case).is_ok() {
            let why: String = text("why").chars().take(400).collect();
            kept.push(json!({ "id": case.id, "class": class, "input": case.input,
                              "want": case.want, "why": why }));
        }
    }
    kept
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
        want: proposed["want"].as_str().unwrap_or_default().to_owned(),
    };
    checked(&case)?;
    cases.push(case);
    let relative = kept_path(root, class);
    let text = serde_json::to_string_pretty(&cases).unwrap_or_default() + "\n";
    crate::attack::put(root, &relative, &text)?;
    Ok(relative)
}

#[cfg(test)]
#[path = "payloads_tests.rs"]
mod tests;
