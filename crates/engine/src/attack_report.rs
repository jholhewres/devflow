//! An attack's report for people and tools: markdown, JSON and SARIF 2.1.0,
//! and an issue draft per family of one root and per confirmed hypothesis
//! no family holds. They are what a person shares, so they carry none of
//! the attack's own words: only the fields devflow sets (status, severity,
//! class, a repository path, a line, the run, who confirmed it, the proof's
//! commits and results), a class devflow does not name by its plain name,
//! and devflow's own sentences for each class of hole and each cause. No
//! payload, secret or exploit code can reach them. The attack's account stays in the run's `attack.json`, for
//! the person to read. devflow publishes none of this: the files are the
//! host's to show and to send where the person says.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{json, Value};

/// The files a report is written as, in its run.
pub const MARKDOWN: &str = "attack-report.md";
pub const JSON: &str = "attack-report.json";
pub const SARIF: &str = "attack-report.sarif";
/// The folder of the issue drafts: one per family, and one per confirmed
/// hypothesis no family holds.
pub const DRAFTS: &str = "drafts";
/// What stands for a field that came in a shape devflow does not set, and
/// for each word of a scanner's text that is not plain.
pub const LEFT_OUT: &str = "<…>";
/// The shortest run of word characters taken for a secret by its shape.
const SHORTEST_SECRET: usize = 32;
/// The longest name a report shows.
const LONGEST_NAME: usize = 40;
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

/// What a report knows besides itself: the paths the commit attacked has.
#[derive(Debug, Default, Clone)]
pub struct Known {
    pub files: BTreeSet<String>,
}

impl Known {
    /// The paths `report` says the commit attacked has.
    pub fn of(report: &Value) -> Known {
        Known {
            files: report["in_repo"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
        }
    }
}

/// The classes a hole is named by: each with what an attacker gets and
/// what shuts it, in devflow's words. Any other class keeps its own name
/// when it is a plain one, said in the words of the class nearest it
/// ([`class_of`], [`worded_as`]).
const CLASSES: &[(&str, &str, &str)] = &[
    (
        "ssrf",
        "The server sends requests to a destination an attacker chooses: internal services, a cloud's metadata or any host it reaches.",
        "Check the destination after resolving it against what it may reach, and refuse private, loopback and link-local addresses.",
    ),
    (
        "injection",
        "Input reaches a query, a command or a template as code: an attacker reads or changes data, or runs what they choose.",
        "Pass input as parameters or arguments, never by building code from text.",
    ),
    (
        "sqli",
        "Input reaches an SQL query as code: an attacker reads or changes data they should not.",
        "Pass input as the query's parameters, never by building the query from text.",
    ),
    (
        "nosqli",
        "Input reaches a document query as an operator: an attacker matches or changes records they should not.",
        "Take only the plain values a query expects from input, and refuse operators in them.",
    ),
    (
        "command-injection",
        "Input reaches a shell or a program's arguments as code: an attacker runs commands on the server.",
        "Run the program with its arguments as a list, never through a shell, and check each against what it may be.",
    ),
    (
        "xss",
        "Input is written into a page as markup or script: an attacker runs script in another user's session.",
        "Escape output for where it is written, and keep a content security policy that refuses inline script.",
    ),
    (
        "csrf",
        "A request another site makes with the user's session is taken as theirs: an attacker acts in their name.",
        "Require a token or a same-site cookie that another site cannot send, on every request that changes state.",
    ),
    (
        "open-redirect",
        "A redirect goes to a destination input chooses: an attacker sends users to their own site under this one's name.",
        "Redirect only to paths of this site, or to destinations on a list.",
    ),
    (
        "traversal",
        "A path from input leaves the folder it should stay in: an attacker reads or writes other files.",
        "Resolve the path, links included, and check it stays under its root before opening it.",
    ),
    (
        "redos",
        "Input makes a pattern's matching take time that grows without bound: one request ties the service up.",
        "Bound the input's size, and use a pattern or an engine whose matching is linear.",
    ),
    (
        "authn",
        "Someone is taken for who they are not: an attacker signs in or keeps a session without the right proof.",
        "Check every proof of identity on the server, its signature, expiry and revocation, on every path that trusts it.",
    ),
    (
        "authz",
        "An action is allowed to someone who should not have it: an attacker reaches another's data or rights.",
        "Check on the server who asks against what they ask for, on every path to the action.",
    ),
    (
        "secrets",
        "A secret is exposed where an attacker can read it.",
        "Move the secret out of the code, the logs and the responses, and rotate it.",
    ),
    (
        "prompt-injection",
        "Text an attacker writes is read by a model as instructions: it acts or answers as the attacker says.",
        "Keep untrusted text as data: mark it as such, give what reads it no tools or rights it does not need, and check the model's actions.",
    ),
    (
        "xxe",
        "An XML document makes the parser read files or reach hosts.",
        "Turn off external entities and DTDs in the parser.",
    ),
    (
        "deserialization",
        "Data from input is turned into objects that run code or change state.",
        "Deserialize only plain data of the types expected, never objects, from input.",
    ),
    (
        "dos",
        "Input makes the service spend time or memory without bound: a request, or a few, tie it up for everyone.",
        "Bound what input may cost before the work starts: its size and depth, the steps it sets off, and the memory it may take.",
    ),
    (
        "crypto",
        "Data is protected by cryptography an attacker can break or get around: a weak hash, a fixed key or nonce, a cipher without integrity.",
        "Use the platform's vetted primitives as documented: a slow salted hash for passwords, random keys and nonces, authenticated encryption.",
    ),
    (
        "transport",
        "A connection trusts a peer it does not check: an attacker in its path reads or changes what passes.",
        "Verify the peer's certificate and name on every connection, and never fall back to plain text.",
    ),
    (
        "info-disclosure",
        "The service tells an attacker what it should not: whether a record or an address exists, internal names, paths or versions, or another user's data.",
        "Answer every caller the same way whatever the cause, and keep the details in logs only the team reads.",
    ),
    (
        "integrity",
        "Content is taken as coming from a source it did not come from, or as whole when it was changed: an attacker passes their own content off under a trusted origin or name.",
        "Keep where content truly came from (its final origin after redirects, its signature or digest), and store or show it only under that source, refusing what does not match.",
    ),
    (
        "other",
        "The attack confirmed this hole with an exploit test: what it lets an attacker do is in the run's attack.json.",
        "The attack's proposed fix is in the run's attack.json.",
    ),
];

/// Other names a class is said by.
const ALSO: &[(&str, &str)] = &[
    ("path-traversal", "traversal"),
    ("directory-traversal", "traversal"),
    ("lfi", "traversal"),
    ("sql-injection", "sqli"),
    ("nosql-injection", "nosqli"),
    ("command", "command-injection"),
    ("rce", "command-injection"),
    ("ssti", "injection"),
    ("idor", "authz"),
    ("access-control", "authz"),
    ("authentication", "authn"),
    ("redirect", "open-redirect"),
    ("secret", "secrets"),
    ("cross-site-scripting", "xss"),
    ("stored-xss", "xss"),
    ("reflected-xss", "xss"),
    ("dom-xss", "xss"),
    ("denial-of-service", "dos"),
    ("tls", "transport"),
    ("ssl", "transport"),
    ("cryptography", "crypto"),
    ("session", "authn"),
    ("jwt", "authn"),
    ("information-disclosure", "info-disclosure"),
    ("info-leak", "info-disclosure"),
    ("information-leak", "info-disclosure"),
    ("data-leak", "info-disclosure"),
    ("data-exposure", "info-disclosure"),
    ("sensitive-data-exposure", "info-disclosure"),
    ("disclosure", "info-disclosure"),
    ("enumeration", "info-disclosure"),
    ("user-enumeration", "info-disclosure"),
    ("provenance", "integrity"),
    ("content-spoofing", "integrity"),
    ("content-injection", "integrity"),
    ("spoofing", "integrity"),
    ("origin-confusion", "integrity"),
    ("origin-spoofing", "integrity"),
    ("tampering", "integrity"),
    ("data-tampering", "integrity"),
    ("data-integrity", "integrity"),
    ("cache-poisoning", "integrity"),
];

/// Parts of a class devflow does not name that tell its family, tried in
/// order when nothing above names it: `header-spoofing` is an integrity
/// hole, `pii-leak` a disclosure, `log-injection` an injection.
const SAID_WITHIN: [(&str, &str); 10] = [
    ("prompt", "prompt-injection"),
    ("provenance", "integrity"),
    ("spoof", "integrity"),
    ("tamper", "integrity"),
    ("poison", "integrity"),
    ("leak", "info-disclosure"),
    ("disclos", "info-disclosure"),
    ("exposure", "info-disclosure"),
    ("enumerat", "info-disclosure"),
    ("inject", "injection"),
];

/// Classes attackers name one kind of hole by, each with the family it is
/// told apart in: a certificate left unchecked is `tls` to one, `ssl` or
/// `transport` to another; a session taken is `authn` or `session`. Who may
/// act (`authz`) stays apart from who one is: a handler may lack either.
const FAMILIES: [(&str, &str); 11] = [
    ("tls", "transport"),
    ("ssl", "transport"),
    ("cryptography", "crypto"),
    ("cipher", "crypto"),
    ("certificate", "transport"),
    ("cert", "transport"),
    ("mitm", "transport"),
    ("insecure-transport", "transport"),
    ("transport", "transport"),
    ("session", "authn"),
    ("jwt", "authn"),
];

/// Families that may name one hole only on the very same line: `crypto` is
/// an unchecked certificate to one attacker, and a weak hash or a fixed key
/// to another a few lines on.
const ON_ONE_LINE: [(&str, &str); 1] = [("crypto", "transport")];

/// Whether two families name one hole when on one line ([`ON_ONE_LINE`]).
pub fn on_one_line(one: &str, other: &str) -> bool {
    ON_ONE_LINE
        .iter()
        .any(|(a, b)| (*a == one && *b == other) || (*a == other && *b == one))
}

/// What is at fault in a hole, as devflow names it, each with the one
/// change at the root that shuts every hole it causes, in devflow's words.
/// The attacker names one per hypothesis (`cause`); a family's fix is the
/// cause its confirmed variants share.
pub const CAUSES: [(&str, &str); 15] = [
    (
        "hand-kept-blocklist",
        "Build the blocked address ranges from the IANA special-purpose address registries for IPv4 and IPv6, and test each of their entries, instead of a list of private, loopback and link-local ranges kept by hand.",
    ),
    (
        "check-then-connect",
        "Resolve the name once, check every address it resolves to, and connect to the address checked, so nothing changes between the check and the connection.",
    ),
    (
        "unchecked-redirect",
        "Check each redirect's destination as the first request's is checked, and bound how many are followed.",
    ),
    (
        "pattern-parsed-markup",
        "Parse the markup with a real HTML parser and keep only what a browser renders, instead of matching patterns over the text.",
    ),
    (
        "unescaped-output",
        "Escape output for where it is written, with the template's own escaping, and never mark input as safe markup.",
    ),
    (
        "text-built-code",
        "Pass input as parameters or an argument list, never by building a query, a command or a template from text.",
    ),
    (
        "super-linear-work",
        "Replace the work whose cost grows faster than its input with one linear pass, a single cursor or a parser, and bound the input's size.",
    ),
    (
        "unbounded-input",
        "Bound what input may cost before the work starts: its size and depth, the steps and calls it sets off, and the memory it may take.",
    ),
    (
        "unverified-peer",
        "Verify the peer's certificate and name: turn the certificate check back on, and give the client the authority that signs the server's certificate.",
    ),
    (
        "unverified-token",
        "Verify every token's signature, issuer, audience and expiry on the server before trusting any of its claims.",
    ),
    (
        "missing-ownership-check",
        "Check on the server that the caller may act on the very record asked for, on every path to it.",
    ),
    (
        "secret-in-reach",
        "Move the secret to a store read at run time, out of the code, the environment others read, the logs and the responses, and rotate it.",
    ),
    (
        "credentials-in-url",
        "Refuse a URL that carries credentials, or strip them, before it is stored, logged or followed.",
    ),
    (
        "unresolved-path",
        "Resolve the path, links included, and check it stays under its root before opening it.",
    ),
    (
        "origin-not-kept",
        "Keep the final origin content came from after redirects, and store or show it under that origin only, or refuse a redirect to another one.",
    ),
];

/// A cause as devflow names it ([`CAUSES`]), whatever its case or
/// separators; `None` for any other.
pub fn cause_of(said: &str) -> Option<&'static str> {
    let said = said.trim().to_ascii_lowercase().replace(['_', ' '], "-");
    CAUSES
        .iter()
        .map(|(name, _)| *name)
        .find(|name| *name == said)
}

/// The fix devflow says for a cause it names.
fn cause_fix(cause: &str) -> Option<&'static str> {
    CAUSES
        .iter()
        .find(|(name, _)| *name == cause)
        .map(|(_, fix)| *fix)
}

/// The family a hypothesis' class is told apart in: its name as devflow
/// says it ([`ALSO`]), the one its neighbours share ([`FAMILIES`]), or the
/// one a part of it tells ([`SAID_WITHIN`]). Any other class is a family of
/// its own, whatever its case or separators.
pub fn family(class: &str) -> String {
    let said = class.trim().to_ascii_lowercase().replace(['_', ' '], "-");
    let said = ALSO
        .iter()
        .find(|(also, _)| *also == said)
        .map_or(said.clone(), |(_, class)| (*class).to_owned());
    let said = FAMILIES
        .iter()
        .find(|(name, _)| *name == said)
        .map_or(said, |(_, family)| (*family).to_owned());
    if named(&said) {
        return said;
    }
    SAID_WITHIN
        .iter()
        .find(|(part, _)| said.contains(part))
        .map_or(said, |(_, family)| (*family).to_owned())
}

/// Whether devflow names `class` and has its words for it.
fn named(class: &str) -> bool {
    CLASSES.iter().any(|(name, _, _)| *name == class)
}

/// A class devflow does not name, as a report shows it: a word or a few of
/// lowercase letters joined by hyphens, no digit, so no token, address or
/// path an attacker set there; any other is `other`.
fn unnamed(said: &str) -> bool {
    (2..=LONGEST_NAME).contains(&said.len())
        && said.chars().all(|ch| ch.is_ascii_lowercase() || ch == '-')
        && said
            .split('-')
            .all(|part| !part.is_empty() && part.len() <= 24)
}

/// A hypothesis' class as a report shows it: its family ([`family`]), which
/// devflow names or which keeps its own name when it is a plain one
/// ([`unnamed`]); `other` when it is neither.
fn class_of(value: &Value) -> String {
    let said = family(value.as_str().unwrap_or_default());
    if named(&said) || unnamed(&said) {
        said
    } else {
        "other".to_owned()
    }
}

/// What an attacker gets from a class of hole, and what shuts it.
fn said_of(class: &str) -> (&'static str, &'static str) {
    CLASSES
        .iter()
        .find(|(name, _, _)| *name == class)
        .map_or(("", ""), |(_, impact, fix)| (*impact, *fix))
}

/// The class devflow names whose words a hypothesis is said in: its own,
/// or for a class devflow does not name, the one its attacker said it is
/// nearest (`near`); `other` when there is none.
fn worded_as(class: &str, one: &Value) -> &'static str {
    let devflows = |said: &str| {
        CLASSES
            .iter()
            .map(|(name, _, _)| *name)
            .find(|name| *name == said && *name != "other")
    };
    let near = family(one["near"].as_str().unwrap_or_default());
    devflows(class)
        .or_else(|| devflows(&near))
        .unwrap_or("other")
}

/// A sentence as it reads after a colon: its first letter lowercase.
fn lowered(sentence: &str) -> String {
    let mut chars = sentence.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_lowercase().chain(chars).collect()
    })
}

/// What a hypothesis of `class` lets an attacker do, as its `status` allows
/// saying it: only a confirmed one is said to be there. A class devflow
/// does not name is said in the words of the one nearest it ([`worded_as`]).
fn impact_of(class: &str, status: &str, one: &Value) -> String {
    let class = worded_as(class, one);
    let (impact, _) = said_of(class);
    let other = class == "other";
    match status {
        "confirmed" => impact.to_owned(),
        "refuted" if other => "Refuted: the hole is not there. What it would have let an attacker do is in the run's attack.json.".to_owned(),
        "refuted" => format!("Refuted: the hole is not there. Were it there, {}", lowered(impact)),
        _ if other => "Not confirmed: no exploit test showed it. What it would let an attacker do is in the run's attack.json.".to_owned(),
        _ => format!("Not confirmed: no exploit test showed it. Were it there, {}", lowered(impact)),
    }
}

/// What shuts a hypothesis of `class`, as its `status` allows: a refuted
/// one has nothing to fix; any other, the fix of the cause its attacker
/// named ([`CAUSES`]), as a family's, else its class's.
fn fix_of(class: &str, status: &str, one: &Value) -> &'static str {
    match status {
        "refuted" => "Nothing to fix: what stops it is in the run's attack.json.",
        _ => cause_of(one["cause"].as_str().unwrap_or_default())
            .and_then(cause_fix)
            .unwrap_or_else(|| said_of(worded_as(class, one)).1),
    }
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

/// A word of prose: letters, with digits only in a short one (`sha256`),
/// hyphens and apostrophes only between them, and not a long run whose
/// case changes as a token's does.
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
        && chars.len() <= LONGEST_NAME
        && (digits == 0 || chars.len() < SHORTEST_OPAQUE)
        && !(chars.len() >= 16 && inner_upper >= 4)
}

/// A number: `42`, `1.5`, a version `2.1.0` or `v2.1.0`; never four parts
/// (an address) nor nine digits (a phone).
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
const CLOSING: [char; 17] = [
    ')', ']', '"', '\'', '`', '”', '’', '»', '*', '.', ',', ';', ':', '!', '?', '…', '–',
];
/// What of that is kept: sentence punctuation, never a quote or markup.
const KEPT_AROUND: [char; 10] = ['(', ')', '.', ',', ';', ':', '!', '?', '…', '–'];

/// A scanner's own text (its fix, `upgrade example-parser to 2.1.0`) as a
/// report shows it: each word kept only when it is a plain word or a
/// number; any other (code, a URL, a path, an address, a token) is
/// [`LEFT_OUT`], one after another said once.
pub fn plain(text: &str) -> String {
    let mut said: Vec<String> = Vec::new();
    for word in text.split_whitespace() {
        let opened = word.trim_start_matches(OPENING);
        let core = opened.trim_end_matches(CLOSING);
        let around =
            |part: &str| -> String { part.chars().filter(|ch| KEPT_AROUND.contains(ch)).collect() };
        let before = around(&word[..word.len() - opened.len()]);
        let after = around(&opened[core.len()..]);
        let shown = if core.is_empty() {
            format!("{before}{after}")
        } else if plain_word(core) || number(core) {
            format!("{before}{core}{after}")
        } else {
            format!("{before}{LEFT_OUT}{after}")
        };
        if shown == LEFT_OUT && said.last().is_some_and(|last| last == LEFT_OUT) {
            continue;
        }
        if !shown.is_empty() {
            said.push(shown);
        }
    }
    said.join(" ")
}

/// A field devflow sets, kept when it is one of `words`.
fn one_of(value: &Value, words: &[&str]) -> Value {
    match value.as_str() {
        Some(word) if words.contains(&word) => json!(word),
        _ => Value::Null,
    }
}

/// A name devflow or the person set (a repository, a scanning tool, a
/// finding's id): one word of `[A-Za-z0-9_-]` not shaped like a secret.
fn name_of(value: &Value) -> Value {
    match value.as_str() {
        Some(word)
            if (1..=LONGEST_NAME).contains(&word.len())
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

/// A hypothesis' id as the attack numbers them: `h1`, `s2`, and `h3-2`
/// for an id an attacker said twice.
fn id_of(value: &Value) -> Value {
    let digits = |part: &str| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit());
    match value.as_str() {
        Some(id) if id.len() <= 12 && id.starts_with(|ch: char| ch.is_ascii_lowercase()) => {
            let (number, again) = id[1..].split_once('-').unwrap_or((&id[1..], "0"));
            if number.len() <= 7 && digits(number) && again.len() <= 2 && digits(again) {
                json!(id)
            } else {
                Value::Null
            }
        }
        _ => Value::Null,
    }
}

/// A run as devflow stamps it: `20261119T120000Z`, or `-2` after it for a
/// second run of that second.
fn run_of(value: &Value) -> Value {
    let Some(run) = value.as_str() else {
        return Value::Null;
    };
    let (stamp, again) = run.split_once('-').unwrap_or((run, "0"));
    let bytes = stamp.as_bytes();
    let stamped = bytes.len() == 16
        && bytes[8] == b'T'
        && bytes[15] == b'Z'
        && bytes[..8]
            .iter()
            .chain(&bytes[9..15])
            .all(u8::is_ascii_digit);
    let again = (1..=2).contains(&again.len()) && again.chars().all(|ch| ch.is_ascii_digit());
    if stamped && again {
        json!(run)
    } else {
        Value::Null
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
                && !word.contains("//")
                && !secret_shaped(word) =>
        {
            json!(word)
        }
        _ => Value::Null,
    }
}

/// A repository path, only one the commit attacked has (`in_repo`): what
/// the attack names that is not there, a file it had written since
/// included, is its own word and may be anything. Found or not, it is relative, with no `..`, nothing
/// that ends a cell or a code span, and no part shaped like a secret.
fn repo_path(value: &Value, known: &Known) -> Value {
    let Some(file) = value.as_str() else {
        return Value::Null;
    };
    let inert = |ch: char| !(ch.is_control() || matches!(ch, '`' | '|' | '\\' | '<' | '>'));
    let shown = known.files.contains(file)
        && (1..=240).contains(&file.len())
        && !file.starts_with('/')
        && !file.contains("://")
        && file.chars().all(inert)
        && file
            .split('/')
            .all(|part| !matches!(part, "" | "." | "..") && !secret_shaped(part));
    if shown {
        json!(file)
    } else {
        Value::Null
    }
}

/// A path as a SARIF location's URI: each byte outside what a URI keeps as
/// it is, percent-encoded.
fn uri_of(file: &str) -> String {
    file.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                (byte as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
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

/// A proof's side as a report shows it: its commit and its result.
fn side(value: &Value) -> Value {
    json!({
        "commit": commit(&value["commit"]),
        "result": one_of(&value["result"], &["red", "green", "skipped", "error"]),
    })
}

/// Who an attacker is, as a report names it: its agent, never its model.
fn agent_of(found_by: &Value) -> Value {
    let said = found_by[0].as_str().unwrap_or_default();
    name_of(&json!(said.split('/').next().unwrap_or_default()))
}

/// What a hypothesis took in, as a report shows each, said once: one an
/// earlier run kept by its id and run there, its item and how it had ended;
/// an attacker's own by the id its attacker gave it (`said_as`), who that
/// was and the run that merged it. Each with its class and line. One it
/// cannot name is left out: attack.json keeps it.
fn merged_shown(one: &Value) -> Option<Vec<Value>> {
    let merged = one["merged"].as_array()?;
    let mut shown: Vec<Value> = Vec::new();
    for gone in merged {
        let (id, said, run) = (
            id_of(&gone["id"]),
            id_of(&gone["said_as"]),
            run_of(&gone["run"]),
        );
        let entry = if !id.is_null() && !run.is_null() {
            json!({
                "id": id, "run": run, "item": name_of(&gone["again"]["item"]),
                "was": one_of(&gone["again"]["was"], &STATUSES),
                "class": class_of(&gone["class"]), "line": gone["line"].as_u64(),
            })
        } else if id.is_null() && !said.is_null() && !run.is_null() {
            json!({
                "said_as": said, "by": agent_of(&gone["found_by"]), "run": run,
                "class": class_of(&gone["class"]), "line": gone["line"].as_u64(),
            })
        } else {
            continue;
        };
        if !shown.contains(&entry) {
            shown.push(entry);
        }
    }
    Some(shown)
}

/// How the run that confirmed or refuted a hypothesis proved it: by an
/// assertion on what the code does, or by `timing`, read over several runs
/// with less confidence. `None` when devflow's sandbox or the session ran
/// nothing.
fn proof_kind(one: &Value) -> Value {
    if one_of(&one["verified"]["by"], &["sandbox", "session"]).is_null() {
        return Value::Null;
    }
    json!(if one["exploit"]["timing"] == true {
        "timing"
    } else {
        "assertion"
    })
}

/// A hypothesis as a report shows it: only fields devflow sets, the
/// sentences devflow says of its class as its status allows, and the
/// repositories a flow's fixes touch.
fn shown(one: &Value, known: &Known) -> Value {
    let class = class_of(&one["class"]);
    let status = one_of(&one["status"], &STATUSES);
    let said = status.as_str().unwrap_or("not_run");
    let proof = &one["proof"];
    let timing = &one["verified"]["timing"];
    json!({
        "id": id_of(&one["id"]), "status": status,
        "severity": one_of(&one["severity"], &SEVERITIES),
        "estimated_severity": one_of(&one["estimated_severity"], &SEVERITIES),
        "class": class, "cause": cause_of(one["cause"].as_str().unwrap_or_default()),
        "file": repo_path(&one["file"], known), "line": one["line"].as_u64(),
        "impact": impact_of(&class, said, one), "fix": fix_of(&class, said, one),
        "verified_by": one_of(&one["verified"]["by"], &["sandbox", "session"]),
        "proof_kind": proof_kind(one),
        "timing": timing["runs"].as_u64().map(|runs| json!({
            "runs": runs, "red": timing["red"].as_u64().unwrap_or_default(),
        })),
        "proof": (!proof.is_null()).then(|| json!({
            "base": side(&proof["base"]), "head": side(&proof["head"]),
            "stack": proof["stack"].as_bool(),
        })),
        "fixes_in": one["fixes"].as_array().map(|fixes| {
            fixes.iter().map(|fix| name_of(&fix["repo"])).collect::<Vec<_>>()
        }),
        "merged": merged_shown(one),
        "family": Value::Null,
    })
}

/// Each confirmed hypothesis with an exploit test, and what holds it: the
/// session's run (`evidence`, green from then on) or the sandbox's proof
/// (`proof`). The test's name is the attack's own words, kept in attack.json.
fn exploits_shown(report: &Value, known: &Known) -> Vec<Value> {
    report["hypotheses"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|one| one["status"] == "confirmed" && one["exploit"]["test"].is_string())
        .map(|one| {
            let by = one_of(&one["verified"]["by"], &["sandbox", "session"]);
            let held_by = if by == "sandbox" { "proof" } else { "evidence" };
            json!({
                "id": id_of(&one["id"]), "file": repo_path(&one["file"], known),
                "line": one["line"].as_u64(), "verified_by": by, "held_by": held_by,
            })
        })
        .collect()
}

/// The hypotheses as [`shown`], each with the family it is one of.
fn hypotheses(report: &Value, known: &Known) -> Vec<Value> {
    let mut shown: Vec<Value> = report["hypotheses"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|one| shown(one, known))
        .collect();
    for (at, members) in roots(report).iter().enumerate() {
        for member in members {
            if let Some(one) = shown.get_mut(*member) {
                one["family"] = json!(format!("f{}", at + 1));
            }
        }
    }
    shown
}

/// A severity's rank: `critical` first.
fn rank(severity: &Value) -> usize {
    SEVERITIES
        .iter()
        .position(|one| severity == *one)
        .unwrap_or(SEVERITIES.len())
}

/// What one hypothesis says is at fault, compared: the cause devflow names
/// ([`cause_of`]), else the function, rule or list its attacker named
/// (`root`) as the code writes it, without `()` or quotes; `None` when it
/// says neither.
fn basis_of(one: &Value) -> Option<String> {
    if let Some(cause) = cause_of(one["cause"].as_str().unwrap_or_default()) {
        return Some(format!("cause:{cause}"));
    }
    let root = one["root"]
        .as_str()
        .unwrap_or_default()
        .trim()
        .trim_matches(|ch: char| matches!(ch, '`' | '"' | '\''))
        .trim_end_matches("()")
        .to_ascii_lowercase();
    (!root.is_empty()).then(|| format!("root:{root}"))
}

/// A hypothesis' file as families compare it: no `./`.
fn family_file(one: &Value) -> String {
    one["file"]
        .as_str()
        .unwrap_or_default()
        .trim()
        .trim_start_matches("./")
        .to_owned()
}

/// The hypotheses of one root, each a list of their places in the report:
/// two or more **confirmed** of one file and one family of class
/// ([`family`]) whose attacker named one cause for them, the same function,
/// rule or list ([`basis_of`]). One that names none joins the only root of
/// its file and family, else stands with the others that name none.
/// Inputs that slip past one check, one list or one parser are variants of
/// one hole, and one fix at its root shuts them all; a refuted, tried or
/// not_run one is no variant. In the order the report first names each.
pub fn roots(report: &Value) -> Vec<Vec<usize>> {
    let list = report["hypotheses"].as_array().cloned().unwrap_or_default();
    // Each group: its file, family of class, what is at fault, and members.
    let mut groups: Vec<(String, String, Option<String>, Vec<usize>)> = Vec::new();
    let mut loose: Vec<(usize, String, String)> = Vec::new();
    for (at, one) in list.iter().enumerate() {
        let file = family_file(one);
        let class = one["class"].as_str().unwrap_or_default().trim();
        if one["status"] != "confirmed" || file.is_empty() || class.is_empty() {
            continue;
        }
        let family = family(class);
        let Some(basis) = basis_of(one) else {
            loose.push((at, file, family));
            continue;
        };
        match groups
            .iter_mut()
            .find(|(f, c, b, _)| *f == file && *c == family && b.as_deref() == Some(&basis))
        {
            Some(group) => group.3.push(at),
            None => groups.push((file, family, Some(basis), vec![at])),
        }
    }
    for (at, file, family) in loose {
        let based: Vec<usize> = (0..groups.len())
            .filter(|at| {
                let (f, c, b, _) = &groups[*at];
                *f == file && *c == family && b.is_some()
            })
            .collect();
        let none = groups
            .iter()
            .position(|(f, c, b, _)| *f == file && *c == family && b.is_none());
        match (based.as_slice(), none) {
            ([only], _) => groups[*only].3.push(at),
            (_, Some(group)) => groups[group].3.push(at),
            _ => groups.push((file, family, None, vec![at])),
        }
    }
    let mut roots: Vec<Vec<usize>> = groups
        .into_iter()
        .map(|(_, _, _, mut members)| {
            members.sort_unstable();
            members
        })
        .filter(|members| members.len() >= 2)
        .collect();
    roots.sort_by_key(|members| members[0]);
    roots
}

/// The cause the most of `members` name, devflow's name for it; the first
/// named on a tie. `None` when none names one devflow knows.
fn shared_cause(members: &[&Value]) -> Option<&'static str> {
    let named: Vec<&'static str> = members
        .iter()
        .filter_map(|one| cause_of(one["cause"].as_str().unwrap_or_default()))
        .collect();
    let times = |cause: &str| named.iter().filter(|other| **other == cause).count();
    let most = named.iter().map(|cause| times(cause)).max()?;
    named.iter().copied().find(|cause| times(cause) == most)
}

/// The one fix a family's variants share, in devflow's words: their cause's
/// ([`CAUSES`]), else their class's, else where the attack's are.
fn family_fix(class: &str, first: &Value, cause: Option<&str>) -> &'static str {
    if let Some(fix) = cause.and_then(cause_fix) {
        return fix;
    }
    match worded_as(class, first) {
        "other" => "The attack's proposed fixes are in the run's attack.json: one change at the root should shut every variant.",
        worded => said_of(worded).1,
    }
}

/// Each family of [`roots`] as a report shows it: its id, class, file and
/// cause, its confirmed variants, the worst severity among them, what an
/// attacker gets, the one fix (its cause's, [`family_fix`]), and whether
/// one of them was proven only by timing.
fn families(report: &Value, known: &Known) -> Vec<Value> {
    let list = report["hypotheses"].as_array().cloned().unwrap_or_default();
    roots(report)
        .iter()
        .enumerate()
        .map(|(at, members)| {
            let variants: Vec<&Value> = members.iter().map(|member| &list[*member]).collect();
            let first = variants[0];
            let class = class_of(&first["class"]);
            let cause = shared_cause(&variants);
            let severity = variants
                .iter()
                .map(|one| one_of(&one["severity"], &SEVERITIES))
                .min_by_key(rank)
                .unwrap_or(Value::Null);
            json!({
                "id": format!("f{}", at + 1), "class": class, "cause": cause,
                "file": repo_path(&first["file"], known),
                "variants": variants.iter().map(|one| json!({
                    "id": id_of(&one["id"]),
                    "status": one_of(&one["status"], &STATUSES),
                    "severity": one_of(&one["severity"], &SEVERITIES),
                    "line": one["line"].as_u64(),
                })).collect::<Vec<_>>(),
                "confirmed": variants.len(), "severity": severity,
                "impact": impact_of(&class, "confirmed", first),
                "fix": family_fix(&class, first, cause),
                "timing": variants.iter().any(|one| proof_kind(one) == "timing"),
            })
        })
        .collect()
}

/// Whether a cap, of time or dollars, ended an attacker's turn.
fn run_cap_hit(report: &Value) -> bool {
    report["budget"]["run_cap_hit"] == true
        || report["attackers"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|one| one["cap_hit"] == true)
}

/// Each hole carried to the next run as a report shows it: the run and id
/// that showed it, how it ended there, its class, severity and place, and
/// why it was carried ([`crate::attack::CARRIED`]).
fn carried(report: &Value, known: &Known) -> Vec<Value> {
    report["carried"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|one| {
            json!({
                "id": id_of(&one["again"]["id"]), "run": run_of(&one["again"]["run"]),
                "item": name_of(&one["again"]["item"]),
                "was": one_of(&one["status"], &STATUSES),
                "severity": one_of(&one["severity"], &SEVERITIES),
                "class": class_of(&one["class"]),
                "file": repo_path(&one["file"], known), "line": one["line"].as_u64(),
                "carried": one_of(&one["carried"], &crate::attack::CARRIED),
            })
        })
        .collect()
}

/// Why a hole was carried, as a line says it.
fn carried_why(report: &Value, why: &Value) -> String {
    match why.as_str() {
        Some("cap") => format!(
            "past the cap of {} run again, the most severe first; it runs first among its severity next time",
            report["run_again_cap"].as_u64().unwrap_or_default()
        ),
        Some("not_named") => "not run before, and not named again by the attack".to_owned(),
        Some("no_exploit") => {
            "its exploit is not in the run that kept it, until an attack writes it again".to_owned()
        }
        _ => "carried".to_owned(),
    }
}

/// Each carried hole as one line: the run and id that showed it, how it
/// ended there, and why it is carried.
fn carried_lines(report: &Value, carried: &[Value]) -> String {
    carried
        .iter()
        .map(|one| {
            format!(
                "- {} of run {} ({}, {} {} at `{}:{}`): {}\n",
                cell(&one["id"]),
                cell(&one["run"]),
                cell(&one["was"]),
                cell(&one["severity"]),
                cell(&one["class"]),
                cell(&one["file"]),
                one["line"].as_u64().unwrap_or(1),
                carried_why(report, &one["carried"])
            )
        })
        .collect()
}

/// The report as JSON: the run, its verdict and numbers, whether a cap
/// ended a turn, every hypothesis as [`shown`] and the families they make,
/// and the holes carried to the next run.
pub fn json_of(report: &Value, known: &Known) -> Value {
    json!({
        "item": report["item"], "run": report["run"], "base": report["base"], "head": report["head"],
        "mode": report["mode"], "verdict": report["verdict"], "counts": report["counts"],
        "metrics": report["metrics"], "profile": report["profile"],
        "run_cap_hit": run_cap_hit(report),
        "run_again": report["run_again"].as_u64(),
        "run_again_cap": report["run_again_cap"].as_u64(),
        "run_again_capped": report["run_again_capped"].as_u64(),
        "carried": carried(report, known),
        "hypotheses": hypotheses(report, known),
        "families": families(report, known),
        "exploits": exploits_shown(report, known),
        "scanner": {
            "reachable": scanned(report, known, true),
            "rest": scanned(report, known, false),
        },
    })
}

/// The scanner findings the attack called reachable, or the rest: the
/// scanner's own names, and its own fix in plain words.
fn scanned(report: &Value, known: &Known, reachable: bool) -> Vec<Value> {
    report["scanner"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|one| (one["reachable"] == true) == reachable)
        .map(|one| {
            json!({
                "id": id_of(&one["id"]), "tool": name_of(&one["tool"]),
                "rule": tool_name(&one["rule"]), "package": tool_name(&one["package"]),
                "file": repo_path(&one["file"], known), "line": one["line"].as_u64(),
                "severity": one_of(&one["severity"], &SEVERITIES),
                "reachable": one["reachable"].as_bool(), "fix": plain(text(one, "fix")),
            })
        })
        .collect()
}

/// A field as a markdown cell or line shows it.
/// Where the project keeps its threat model, when the attack proposed an
/// update to it: shown only in devflow's own shape, a plain folder of the
/// project and `threat-model.md`.
fn threat_path(report: &Value) -> Option<String> {
    let path = report["threat_model"]["path"].as_str()?;
    let folder = path.strip_suffix("/threat-model.md")?;
    let plain = !folder.is_empty()
        && !folder.starts_with('/')
        && folder.split('/').all(|part| {
            !part.is_empty()
                && part != ".."
                && part
                    .chars()
                    .all(|one| one.is_ascii_alphanumeric() || "._-".contains(one))
        });
    plain.then(|| path.to_owned())
}

fn cell(value: &Value) -> String {
    match value {
        Value::String(said) => said.replace('|', "\\|").replace('\n', " "),
        Value::Null => LEFT_OUT.to_owned(),
        other => other.to_string(),
    }
}

/// Who ran a hypothesis's exploit and how it ended, apart from its proof:
/// the sandbox, or the session's run, confirmed or refuted it.
fn ran_by(one: &Value) -> String {
    let by = match text(one, "verified_by") {
        "sandbox" => "devflow's sandbox",
        "session" => "the session's run",
        _ => return "not run by devflow".to_owned(),
    };
    let ran = match text(one, "status") {
        "confirmed" => format!("confirmed by {by}"),
        "refuted" => format!("refuted by {by}"),
        _ => return "not run by devflow".to_owned(),
    };
    // A proof by time is read over several runs, and trusted less.
    match (text(one, "proof_kind"), one["timing"]["runs"].as_u64()) {
        ("timing", Some(runs)) => {
            let red = one["timing"]["red"].as_u64().unwrap_or_default();
            let (color, count) = if one["status"] == "confirmed" {
                ("red", red)
            } else {
                ("green", runs.saturating_sub(red))
            };
            format!("{ran}, by timing: {color} in {count} of {runs} runs, less sure")
        }
        ("timing", None) => format!("{ran}, by timing: less sure"),
        _ => ran,
    }
}

/// A severity as a cell shows it: a refuted one's estimate beside it.
fn severity_cell(one: &Value) -> String {
    match one["estimated_severity"].as_str() {
        Some(estimate) => format!("{} (est. {estimate})", cell(&one["severity"])),
        None => cell(&one["severity"]),
    }
}

/// Whether an entry of what a hypothesis took in was merged in `run`, the
/// report's own: an attacker's hypothesis, named by the id it gave it.
fn merged_in(gone: &Value, run: &str) -> bool {
    gone["said_as"].is_string() && gone["run"] == run
}

/// Each hypothesis that took in what earlier runs kept, one line each: how
/// many, and each one's id and the run that kept it, or the id an attacker
/// of that run gave it.
fn merged_lines(shown: &[Value], run: &str) -> String {
    shown
        .iter()
        .filter_map(|one| {
            let each: Vec<String> = one["merged"]
                .as_array()?
                .iter()
                .filter(|gone| !merged_in(gone, run))
                .map(|gone| match gone["said_as"].as_str() {
                    Some(said) => format!(
                        "what {} numbered {said} in run {}",
                        cell(&gone["by"]),
                        cell(&gone["run"])
                    ),
                    None => format!("{} of run {}", cell(&gone["id"]), cell(&gone["run"])),
                })
                .collect();
            (!each.is_empty()).then(|| {
                format!(
                    "- {} took in {}: {}\n",
                    cell(&one["id"]),
                    each.len(),
                    each.join(", ")
                )
            })
        })
        .collect()
}

/// Each hypothesis that took in another of this run, one line each: each by
/// the id its attacker gave it, with its class and line, never as one of
/// this report's ids.
fn merged_here_lines(shown: &[Value], run: &str) -> String {
    shown
        .iter()
        .filter_map(|one| {
            let each: Vec<String> = one["merged"]
                .as_array()?
                .iter()
                .filter(|gone| merged_in(gone, run))
                .map(|gone| {
                    format!(
                        "what {} numbered {} ({}, line {})",
                        cell(&gone["by"]),
                        cell(&gone["said_as"]),
                        cell(&gone["class"]),
                        cell(&gone["line"])
                    )
                })
                .collect();
            (!each.is_empty())
                .then(|| format!("- {} took in {}\n", cell(&one["id"]), each.join(", ")))
        })
        .collect()
}

/// Each family as one line: its class and file, its confirmed variants,
/// the cause they share when the attack named one, and the one fix.
fn family_lines(families: &[Value]) -> String {
    families
        .iter()
        .map(|family| {
            let variants: Vec<String> = family["variants"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|one| cell(&one["id"]))
                .collect();
            let cause = family["cause"]
                .as_str()
                .map_or_else(String::new, |cause| format!(", cause `{cause}`"));
            format!(
                "- {} {} in `{}`: {} confirmed variants ({}){cause}. One fix: {}\n",
                cell(&family["id"]),
                cell(&family["class"]),
                cell(&family["file"]),
                variants.len(),
                variants.join(", "),
                cell(&family["fix"])
            )
        })
        .collect()
}

/// A proof as a line says it: red at the base, green at HEAD. A confirmed
/// hypothesis not yet proven says so: confirmed is not proven.
fn proof_said(one: &Value) -> String {
    let proof = &one["proof"];
    if proof.is_null() {
        return match text(one, "status") {
            "confirmed" => {
                "not proven yet: once fixed, `prove` runs it at its base and at HEAD".to_owned()
            }
            _ => "not proven by devflow".to_owned(),
        };
    }
    let at = |side: &Value| {
        format!(
            "{} at {}",
            cell(&side["result"]),
            cell(&side["commit"]).chars().take(12).collect::<String>()
        )
    };
    let mut said = format!("{}, {}", at(&proof["base"]), at(&proof["head"]));
    if proof["stack"] == true {
        said.push_str(", on the stack");
    }
    said
}

/// The report as markdown.
pub fn markdown(report: &Value, known: &Known) -> String {
    let counts = &report["counts"];
    // What the attack read, as devflow set it: a work item's change, a range,
    // or a range already in production.
    let mode = ["item", "range", "retro"]
        .into_iter()
        .find(|mode| report["mode"] == *mode)
        .map_or_else(String::new, |mode| format!("{mode} "));
    let carried_count = report["carried"].as_array().map_or(0, Vec::len);
    let carried_said = if carried_count > 0 {
        format!(", {carried_count} carried")
    } else {
        String::new()
    };
    let mut out = format!(
        "# Attack report: {}\n\nRun {}, {mode}{}..{}. Verdict: **{}**. {} confirmed, {} refuted, {} tried, {} not run{carried_said}.\n",
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
    let profile = &report["profile"];
    if profile.is_object() {
        let secs = |key: &str| profile[key].as_u64().unwrap_or_default() / 1_000;
        out.push_str(&format!(
            "Time: {}s in all; {}s before the attack, {}s the attack, {}s run again (while the attack ran), {}s proving what it wrote; of the last two, {}s repeating proofs by time.\n",
            secs("total_ms"),
            secs("prepare_ms"),
            secs("attackers_ms"),
            secs("run_again_ms"),
            secs("proof_ms"),
            secs("timing_ms"),
        ));
    }
    if run_cap_hit(report) {
        out.push_str(
            "A cap ended an attacker's turn (`run_cap_hit`): it may have found more past it.\n",
        );
    }
    if let Some(path) = threat_path(report) {
        out.push_str(&format!(
            "A proposed update to the threat model, `{path}`, is in the run's threat-model.proposed.md, its diff in attack.json: the person's to take or leave.\n"
        ));
    }
    out.push_str(
        "\nThe attack's own account of each hypothesis is in the run's attack.json: this report carries only what devflow sets.\n",
    );
    let reachable = scanned(report, known, true);
    let rest = scanned(report, known, false);
    if !reachable.is_empty() || !rest.is_empty() {
        out.push_str("\n## Scanner findings untrusted input reaches\n\n");
        if reachable.is_empty() {
            out.push_str("None.\n");
        }
        for one in &reachable {
            out.push_str(&format!(
                "- {} {} `{}` in {} at {}:{}. Fix: {}\n",
                cell(&one["severity"]),
                cell(&one["rule"]),
                cell(&one["package"]),
                cell(&one["tool"]),
                cell(&one["file"]),
                one["line"].as_u64().unwrap_or(1),
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
    let shown = hypotheses(report, known);
    let across: Vec<String> = shown
        .iter()
        .filter_map(|one| {
            let repos: Vec<String> = one["fixes_in"].as_array()?.iter().map(cell).collect();
            (!repos.is_empty()).then(|| format!("- {}: {}\n", cell(&one["id"]), repos.join(", ")))
        })
        .collect();
    if !across.is_empty() {
        out.push_str("\n## Fixes on each side of the flow\n\nThe repositories each fix touches; the fixes are in attack.json.\n\n");
        out.push_str(&across.concat());
    }
    let families = families(report, known);
    if !families.is_empty() {
        out.push_str("\n## Holes by root\n\nConfirmed variants of one cause (one function, rule or list) are one hole: one fix at its root shuts them all. A refuted or unconfirmed hypothesis is no variant.\n\n");
        out.push_str(&family_lines(&families));
    }
    let run = text(report, "run");
    let (earlier, here) = (merged_lines(&shown, run), merged_here_lines(&shown, run));
    if !earlier.is_empty() || !here.is_empty() {
        out.push_str("\n## What each hypothesis took in\n\nOne hole named again, merged into the one kept.\n");
    }
    if !earlier.is_empty() {
        out.push_str(
            "\n### From earlier runs\n\nEach by the run that kept it and its id there.\n\n",
        );
        out.push_str(&earlier);
    }
    if !here.is_empty() {
        out.push_str("\n### Merged in this run\n\nAnother attacker's hypothesis at the same place, or one an attacker named again of a hole run again: each by the number its attacker gave it, not this report's ids.\n\n");
        out.push_str(&here);
    }
    let carried = carried(report, known);
    if !carried.is_empty() {
        out.push_str("\n## Carried to the next run\n\nNot run again this time and kept, so no hole is lost: each is named by the run that showed it, and comes back in the next run.\n\n");
        out.push_str(&carried_lines(report, &carried));
    }
    out.push_str(
        "\n| Id | Status | Severity | Class | Where | Ran | Proof |\n|---|---|---|---|---|---|---|\n",
    );
    for one in &shown {
        out.push_str(&format!(
            "| {} | {} | {} | {} | `{}:{}` | {} | {} |\n",
            cell(&one["id"]),
            cell(&one["status"]),
            severity_cell(one),
            cell(&one["class"]),
            cell(&one["file"]),
            one["line"],
            ran_by(one),
            proof_said(one),
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

/// A SARIF location at a shown file and line.
fn location(one: &Value) -> Value {
    json!([{ "physicalLocation": {
        "artifactLocation": { "uri": one["file"].as_str().map_or_else(|| ".".to_owned(), uri_of) },
        "region": { "startLine": one["line"].as_u64().unwrap_or(1).max(1) },
    } }])
}

/// The confirmed hypotheses as SARIF 2.1.0, each at its file and line, and
/// the confirmed holes carried to the next run, said so: shown by the run
/// named, not run again at this HEAD.
pub fn sarif(report: &Value, known: &Known) -> Value {
    let mut results: Vec<Value> = hypotheses(report, known)
        .into_iter()
        .filter(|one| one["status"] == "confirmed")
        .map(|one| {
            let class = text(&one, "class");
            json!({
                "ruleId": format!("attack/{class}"),
                "level": level(text(&one, "severity")),
                "message": { "text": format!(
                    "{class}: confirmed by an exploit test. {}", text(&one, "impact")
                ) },
                "locations": location(&one),
                "properties": { "severity": one["severity"], "verifiedBy": one["verified_by"] },
            })
        })
        .collect();
    results.extend(
        carried(report, known)
            .into_iter()
            .filter(|one| one["was"] == "confirmed")
            .map(|one| {
                let class = text(&one, "class");
                json!({
                    "ruleId": format!("attack/{class}"),
                    "level": level(text(&one, "severity")),
                    "message": { "text": format!(
                        "{class}: confirmed by an exploit test in run {}, carried: not run again at this HEAD.",
                        cell(&one["run"])
                    ) },
                    "locations": location(&one),
                    "properties": { "severity": one["severity"], "carried": one["carried"] },
                })
            }),
    );
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": "devflow-attack", "version": env!("CARGO_PKG_VERSION") } },
            "results": results,
        }],
    })
}

/// What every draft ends with: what it carries, and what it leaves to the
/// person.
const BEFORE_POSTING: &str = "## Before posting\nThis draft carries none of the attack's own words, so no payload or secret goes with it. The attack's account is in the run's attack.json: add what the issue needs in your own words.\n";

/// What a draft says of the hypotheses in it proven only by timing: how
/// many runs agreed, and that such a proof is trusted less. Nothing when
/// none was.
fn timing_caveat(ones: &[&Value]) -> String {
    let timed: Vec<String> = ones
        .iter()
        .filter(|one| one["proof_kind"] == "timing")
        .map(|one| {
            let runs = one["timing"]["runs"]
                .as_u64()
                .map_or_else(String::new, |runs| {
                    let red = one["timing"]["red"].as_u64().unwrap_or_default();
                    format!(", red in {red} of {runs} runs")
                });
            format!("{}{runs}", cell(&one["id"]))
        })
        .collect();
    if timed.is_empty() {
        return String::new();
    }
    format!(
        "\n## Confidence\nProven by timing only, less sure: {}. A proof by time is read over several runs and trusted less than one that counts what the code does, since the machine's load moves it: confirm it by count before posting.\n",
        timed.join("; ")
    )
}

/// Who confirmed a hypothesis, as a draft says it.
fn confirmed_by(one: &Value) -> &'static str {
    match text(one, "verified_by") {
        "sandbox" => "devflow's sandbox, running its exploit test",
        _ => "the session's run of its exploit test",
    }
}

/// A family's draft: one hole, its confirmed variants each with who
/// confirmed it and its proof, and the one fix at its root.
fn family_draft(report: &Value, family: &Value, variants: &[&Value]) -> Value {
    // In the order of their lines, as a reader goes through the file.
    let mut variants = variants.to_vec();
    variants.sort_by_key(|one| one["line"].as_u64().unwrap_or_default());
    let variants = variants.as_slice();
    let lines: Vec<String> = variants.iter().map(|one| one["line"].to_string()).collect();
    let each: String = variants
        .iter()
        .map(|one| {
            format!(
                "- {} at line {}, {}: {}; {}\n",
                cell(&one["id"]),
                one["line"],
                cell(&one["severity"]),
                ran_by(one),
                proof_said(one)
            )
        })
        .collect();
    let cause = family["cause"]
        .as_str()
        .map_or_else(String::new, |cause| format!("**Cause:** `{cause}`\n"));
    let title = format!(
        "[security] {} in {}: {} variants of one hole",
        text(family, "class"),
        cell(&family["file"]),
        variants.len()
    );
    let body = format!(
        "**Severity:** {}\n**Where:** `{}`, lines {}\n**Class:** {}\n{cause}**Found by:** devflow's attack, run {} of {}\n\n## Variants\nOne hole, confirmed {} ways: one change at its root shuts them all.\n{each}\n## Impact\n{}\n\n## Fix\n{}\n{}\n{BEFORE_POSTING}",
        cell(&family["severity"]),
        cell(&family["file"]),
        lines.join(", "),
        text(family, "class"),
        text(report, "run"),
        text(report, "item"),
        variants.len(),
        text(family, "impact"),
        text(family, "fix"),
        timing_caveat(variants),
    );
    json!({ "id": family["id"], "title": title, "severity": family["severity"], "body": body,
            "variants": variants.iter().map(|one| one["id"].clone()).collect::<Vec<_>>() })
}

/// A draft of a confirmed hypothesis no family holds: its class, severity,
/// place, impact, fix and run.
fn one_draft(report: &Value, one: &Value) -> Value {
    let title = format!(
        "[security] {} in {}:{}",
        text(one, "class"),
        cell(&one["file"]),
        one["line"]
    );
    let body = format!(
        "**Severity:** {}\n**Where:** `{}:{}`\n**Class:** {}\n**Found by:** devflow's attack, run {} of {}\n**Confirmed by:** {}\n**Proof:** {}\n\n## Impact\n{}\n\n## Fix\n{}\n{}\n{BEFORE_POSTING}",
        cell(&one["severity"]),
        cell(&one["file"]),
        one["line"],
        text(one, "class"),
        text(report, "run"),
        text(report, "item"),
        confirmed_by(one),
        proof_said(one),
        text(one, "impact"),
        text(one, "fix"),
        timing_caveat(&[one]),
    );
    json!({ "id": one["id"], "title": title, "severity": one["severity"], "body": body })
}

/// The issue drafts, all in devflow's words: one per family, with its
/// variants and the one fix at its root, then one per confirmed hypothesis
/// no family holds.
pub fn drafts(report: &Value, known: &Known) -> Vec<Value> {
    let shown = hypotheses(report, known);
    let mut drafts: Vec<Value> = roots(report)
        .iter()
        .zip(families(report, known))
        .map(|(members, family)| {
            let variants: Vec<&Value> = members
                .iter()
                .filter_map(|member| shown.get(*member))
                .collect();
            family_draft(report, &family, &variants)
        })
        .collect();
    drafts.extend(
        shown
            .iter()
            .filter(|one| one["status"] == "confirmed" && one["family"].is_null())
            .map(|one| one_draft(report, one)),
    );
    drafts
}

/// The confirmed hypotheses whose severity is in `block_on`, as [`shown`]:
/// what fails a CI run.
pub fn held(report: &Value, block_on: &[crate::config::Severity]) -> Vec<Value> {
    hypotheses(report, &Known::of(report))
        .into_iter()
        .filter(|one| one["status"] == "confirmed")
        .filter(|one| {
            crate::findings::severity_of(text(one, "severity"))
                .is_some_and(|severity| block_on.contains(&severity))
        })
        .collect()
}

/// The hypotheses nothing ran, each with its id and why: one the attack did
/// not try, and one tried that no sandbox ran. They prove nothing either
/// way. The why is devflow's own, never the attack's.
pub fn not_run(report: &Value) -> Vec<(String, String)> {
    report["hypotheses"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|one| {
            one["status"] == "not_run"
                || (one["status"] == "tried" && one["ran"]["result"] == "not_run")
        })
        .map(|one| {
            let id = id_of(&one["id"]).as_str().unwrap_or(LEFT_OUT).to_owned();
            if one["status"] == "not_run" {
                return (id, "the attack did not try it".to_owned());
            }
            // devflow's own words for why, never a reason that could carry
            // the exploit's path or output.
            let said = text(&one["ran"], "reason");
            let why = if said.contains("stages.attack.test") {
                "stages.attack.test is not set"
            } else if said.contains("bwrap") || said.contains("docker") {
                "no sandbox the runner has: bwrap with user namespaces, or docker with stages.attack.image"
            } else if said.contains("does not hold steady") {
                "a proof by timing whose runs did not agree"
            } else if said.contains("stack") {
                "a stack is reached only from the docker sandbox"
            } else {
                "its sandbox run did not finish"
            }
            .to_owned();
            (id, why)
        })
        .collect()
}

/// Text as XML holds it, in an attribute or between tags.
fn xml(text: &str) -> String {
    text.chars()
        .filter(|ch| !ch.is_control() || matches!(ch, '\n' | '\t'))
        .map(|ch| match ch {
            '&' => "&amp;".to_owned(),
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '"' => "&quot;".to_owned(),
            '\'' => "&apos;".to_owned(),
            other => other.to_string(),
        })
        .collect()
}

/// The attack as JUnit, a test case per hypothesis: a confirmed one in
/// `block_on` fails, one no sandbox ran is skipped, the rest pass. Each
/// says only what devflow sets.
pub fn junit(report: &Value, block_on: &[crate::config::Severity]) -> String {
    let known = Known::of(report);
    let failing: Vec<Value> = held(report, block_on);
    let skipped: Vec<String> = not_run(report).into_iter().map(|(id, _)| id).collect();
    let mut cases = String::new();
    let shown = hypotheses(report, &known);
    for one in &shown {
        let id = cell(&one["id"]);
        let name = format!(
            "{id} {} at {}:{} ({})",
            text(one, "class"),
            cell(&one["file"]),
            one["line"],
            cell(&one["severity"])
        );
        let body = if failing.iter().any(|held| held == one) {
            format!(
                "<failure type=\"confirmed\" message=\"{}\">{}\n{}</failure>",
                xml(&format!(
                    "{}: confirmed by an exploit test, {} is in block_on",
                    text(one, "class"),
                    cell(&one["severity"])
                )),
                xml(&proof_said(one)),
                xml(text(one, "impact"))
            )
        } else if one["status"] == "not_run" {
            "<skipped message=\"the attack did not try it: it proves nothing either way\"/>"
                .to_owned()
        } else if one["status"] == "tried" && skipped.contains(&id) {
            "<skipped message=\"no sandbox ran its exploit: it proves nothing either way\"/>"
                .to_owned()
        } else {
            String::new()
        };
        cases.push_str(&format!(
            "    <testcase classname=\"devflow-attack.{}\" name=\"{}\">{body}</testcase>\n",
            xml(text(one, "class")),
            xml(&name)
        ));
    }
    let suite = format!("devflow-attack {}", text(report, "item"));
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites name=\"devflow-attack\" tests=\"{n}\" failures=\"{f}\" skipped=\"{s}\">\n  <testsuite name=\"{name}\" tests=\"{n}\" failures=\"{f}\" skipped=\"{s}\">\n{cases}  </testsuite>\n</testsuites>\n",
        n = shown.len(),
        f = failing.len(),
        s = skipped.len(),
        name = xml(&suite),
    )
}

/// The report written in its run as markdown, JSON and SARIF, and its
/// drafts under [`DRAFTS`]; the files' names, relative to the run.
pub fn written(folder: &Path, report: &Value) -> Result<Vec<String>, String> {
    let known = Known::of(report);
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
            .map_or_else(|| format!("draft-{}", at + 1), str::to_owned);
        let said = format!("# {}\n\n{}", text(draft, "title"), text(draft, "body"));
        files.push(put(&format!("{DRAFTS}/{id}.md"), &said)?);
    }
    Ok(files)
}

#[cfg(test)]
#[path = "attack_report_tests.rs"]
mod tests;
