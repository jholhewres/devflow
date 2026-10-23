//! `devpit_devflow_publish`: a review drafted for its pull request, and
//! published there only after the person's yes to that draft.
//!
//! `publish.json`, beside `findings.json`, holds what goes inline — each
//! critical, high and medium on a line the diff shows, one short comment per
//! line whatever its axes — and the one general comment: the nits, what lies
//! outside the diff, the verification and what is good, in the destination's
//! template. `published.json` keeps the ids a second publish edits instead
//! of posting again. Posting is a [`Host`]'s: the app's `gh`, or a test's.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{json, Map, Value};

use crate::config::Verify;
use crate::findings::{self, AXES};
use crate::review::{self, Personas};
use crate::runs;

/// What a publish leaves in the review's run.
pub const DRAFT: &str = "publish.json";
pub const PUBLISHED: &str = "published.json";

/// The most of one finding's text a comment says: short, as a person would.
const MOST_SAID: usize = 280;
/// Far past what a template needs, checked before reading one.
const MOST_TEMPLATE: u64 = 32 * 1024;
/// What a template places, each as `{{name}}`, and `{{#name}}…{{/name}}`
/// around what is left out when it is empty.
pub const SECTIONS: [&str; 6] = [
    "summary",
    "tickets",
    "elsewhere",
    "nits",
    "verification",
    "done_well",
];

const SHAPE: &str = "{ review: \"<the review's folder>/<its run>\", apply?, destination?: github | gitlab | bitbucket, event?: comment | approve | request_changes }";
const FIELDS: [&str; 5] = ["review", "apply", "destination", "event", "project"];

/// Where a review is published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    GitHub,
    GitLab,
    Bitbucket,
}

impl Destination {
    pub const ALL: [Destination; 3] = [
        Destination::GitHub,
        Destination::GitLab,
        Destination::Bitbucket,
    ];

    pub fn word(self) -> &'static str {
        match self {
            Destination::GitHub => "github",
            Destination::GitLab => "gitlab",
            Destination::Bitbucket => "bitbucket",
        }
    }

    pub fn of(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|one| one.word() == word)
    }

    /// Only GitHub is posted to; the others are drafted for a person to paste.
    pub fn posts(self) -> bool {
        self == Destination::GitHub
    }

    fn shipped(self) -> &'static str {
        match self {
            Destination::GitHub => include_str!("../../../flow/publish/github.md"),
            Destination::GitLab => include_str!("../../../flow/publish/gitlab.md"),
            Destination::Bitbucket => include_str!("../../../flow/publish/bitbucket.md"),
        }
    }
}

/// What the review asks of the pull request: a comment, unless the person
/// asked for more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Comment,
    Approve,
    RequestChanges,
}

impl Event {
    pub const ALL: [Event; 3] = [Event::Comment, Event::Approve, Event::RequestChanges];

    /// As the tool takes it.
    pub fn word(self) -> &'static str {
        match self {
            Event::Comment => "comment",
            Event::Approve => "approve",
            Event::RequestChanges => "request_changes",
        }
    }

    /// As GitHub's API takes it.
    pub fn api(self) -> &'static str {
        match self {
            Event::Comment => "COMMENT",
            Event::Approve => "APPROVE",
            Event::RequestChanges => "REQUEST_CHANGES",
        }
    }

    pub fn of(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|one| one.word() == word)
    }
}

/// The tool's input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    /// The review's folder under the project's reviews/, and its run.
    pub label: String,
    pub run: String,
    pub apply: bool,
    pub destination: Destination,
    pub event: Event,
}

impl Asked {
    /// The review as the tool names it.
    pub fn review(&self) -> String {
        format!("{}/{}", self.label, self.run)
    }
}

/// The tool's input, refused with what it takes when it is not that.
pub fn asked(params: &Value) -> Result<Asked, String> {
    let fields = params
        .as_object()
        .ok_or_else(|| format!("publishing takes {SHAPE}"))?;
    if let Some(extra) = fields.keys().find(|key| !FIELDS.contains(&key.as_str())) {
        return Err(format!(
            "`{extra}` is not a field of publishing: it takes {SHAPE}"
        ));
    }
    let review = fields
        .get("review")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    // Both parts are names devpit made, never a path out of the reviews.
    let (label, run) = review
        .split_once('/')
        .filter(|(label, run)| runs::plain_card(label) && runs::seconds_of(run).is_some())
        .ok_or("`review` is a review's folder and run, as devpit_devflow_review answered them: \"pr-42/20261016T120000Z\"")?;
    let word = |key: &str| fields.get(key).filter(|said| !said.is_null());
    let destination = match word("destination") {
        None => Destination::GitHub,
        Some(said) => said
            .as_str()
            .and_then(Destination::of)
            .ok_or("`destination` is github, gitlab or bitbucket")?,
    };
    // Approving or asking for changes is the person's to ask, never a default.
    let event = match word("event") {
        None => Event::Comment,
        Some(said) => said
            .as_str()
            .and_then(Event::of)
            .ok_or("`event` is comment, approve or request_changes")?,
    };
    Ok(Asked {
        label: label.to_owned(),
        run: run.to_owned(),
        apply: fields.get("apply").and_then(Value::as_bool) == Some(true),
        destination,
        event,
    })
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// Text on one line, cut short.
fn short(said: &str) -> String {
    let line = said.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.chars().count() <= MOST_SAID {
        return line;
    }
    let cut: String = line.chars().take(MOST_SAID).collect();
    format!("{}…", cut.trim_end())
}

fn line_of(finding: &Value) -> u64 {
    finding["line"].as_u64().unwrap_or(1).max(1)
}

fn place(finding: &Value) -> String {
    format!("`{}:{}`", text(finding, "file"), line_of(finding))
}

/// Whether a finding is said on the pull request at all: still standing,
/// and not shown wrong by its PoC.
pub fn said_on_pr(finding: &Value, verify: Verify) -> bool {
    findings::standing(finding)
        && findings::weighed(finding, verify).0.is_some()
        && text(&finding["verified"], "result") != "refuted"
}

/// Whether a finding is a comment on its line: a critical, high or medium
/// on a line the diff shows, which the pull request can hold it on.
pub fn inline(finding: &Value) -> bool {
    matches!(text(finding, "severity"), "critical" | "high" | "medium")
        && matches!(text(finding, "anchor"), "added" | "context")
}

/// Whether a finding off the diff's lines deserves a ticket of its own.
pub fn separate_ticket(finding: &Value) -> bool {
    matches!(text(finding, "severity"), "critical" | "high")
}

/// Whether a retro review follows a finding up with a ticket: every medium
/// or worse, as the code is already in production.
pub fn ticketed(finding: &Value) -> bool {
    matches!(text(finding, "severity"), "critical" | "high" | "medium")
}

/// A retro review's follow-up ticket, with the read-only query that shows
/// what its defect touched since the deploy.
fn ticket_of(finding: &Value, verify: Verify) -> Value {
    let mut body = format!(
        "**{}** [{}] {}\n\n{} — {}",
        text(finding, "severity"),
        text(finding, "axis"),
        text(finding, "title"),
        place(finding),
        text(finding, "description")
    );
    let suggestion = text(finding, "suggestion").trim();
    if !suggestion.is_empty() {
        body.push_str(&format!("\n\nFix: {suggestion}"));
    }
    if let Some(verification) = findings::verification_said(finding, verify) {
        body.push_str(&format!("\n\nPoC: {verification}"));
    }
    let impact = text(finding, "impact").trim();
    if !impact.is_empty() {
        let fence = review::fence_for(impact);
        body.push_str(&format!(
            "\n\nImpact in production, read-only:\n{fence}\n{impact}\n{fence}"
        ));
    }
    let mut ticket = json!({
        "title": text(finding, "title"),
        "severity": text(finding, "severity"),
        "file": text(finding, "file"),
        "line": line_of(finding),
        "body": body,
    });
    if !impact.is_empty() {
        ticket["impact"] = json!(impact);
    }
    ticket
}

/// What to do about a finding: its suggestion, else why it matters.
fn fix_of(finding: &Value) -> &str {
    match text(finding, "suggestion").trim() {
        "" => text(finding, "description"),
        said => said,
    }
}

/// One finding as its line's comment says it.
fn inline_said(finding: &Value, verify: Verify) -> String {
    let mut said = format!(
        "**{}** [{}] {}",
        text(finding, "severity"),
        text(finding, "axis"),
        short(text(finding, "title"))
    );
    if let Some(verification) = findings::verification_said(finding, verify) {
        said.push_str(&format!(" — {}", short(&verification)));
    }
    let fix = short(fix_of(finding));
    if !fix.is_empty() {
        said.push_str(&format!("\n{fix}"));
    }
    said
}

/// Where a finding off the diff's lines sits, as the general comment says it.
fn off_the_diff(finding: &Value) -> &'static str {
    match text(finding, "anchor") {
        "not_in_diff" => "in a file this change does not touch",
        _ => "outside the lines this change shows",
    }
}

fn listed(lines: &[String]) -> String {
    lines.join("\n")
}

/// The general comment's sections, by name.
fn sections(
    kept: &Value,
    said: &[&Value],
    inline_count: usize,
    verify: Verify,
) -> (BTreeMap<&'static str, String>, Vec<String>, Vec<Value>) {
    let mut nits = Vec::new();
    let mut elsewhere = Vec::new();
    let mut elsewhere_lines = Vec::new();
    for finding in said.iter().filter(|finding| !inline(finding)) {
        if matches!(text(finding, "severity"), "low" | "info") {
            nits.push(format!(
                "{}. {} {} — {}",
                nits.len() + 1,
                place(finding),
                short(text(finding, "title")),
                short(fix_of(finding))
            ));
            continue;
        }
        let ticket = separate_ticket(finding);
        let mut line = format!(
            "- **{}** [{}] {} {} — {}, so it has no line here. {}",
            text(finding, "severity"),
            text(finding, "axis"),
            place(finding),
            short(text(finding, "title")),
            off_the_diff(finding),
            short(fix_of(finding))
        );
        if ticket {
            line.push_str(" Worth a separate ticket.");
        }
        elsewhere_lines.push(line);
        elsewhere.push(json!({
            "file": text(finding, "file"),
            "line": line_of(finding),
            "severity": text(finding, "severity"),
            "title": text(finding, "title"),
            "ticket": ticket,
        }));
    }
    let mut verification: Vec<String> = [
        ("tests", "Tests"),
        ("evidence", "Evidence"),
        ("not_checked", "Not checked"),
    ]
    .iter()
    .filter(|(key, _)| !text(&kept["verification"], key).trim().is_empty())
    .map(|(key, name)| {
        let said = text(&kept["verification"], key).trim().replace('\n', "; ");
        format!("- {name}: {said}")
    })
    .collect();
    let list = kept["findings"].as_array().map_or(&[][..], Vec::as_slice);
    let standing = list.iter().filter(|finding| findings::standing(finding));
    verification.extend(standing.filter_map(|finding| {
        findings::verification_said(finding, verify).map(|said| {
            format!(
                "- {} {}: {}",
                place(finding),
                short(text(finding, "title")),
                short(&said)
            )
        })
    }));
    let done_well: Vec<String> = kept["done_well"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|said| format!("- {}", short(said)))
        .collect();
    let plural =
        |count: usize, one: &str| format!("{count} {one}{}", if count == 1 { "" } else { "s" });
    let summary = format!(
        "**devpit review** of {}: {} on the lines, {}, {} outside the diff.",
        text(kept, "head").get(..12).unwrap_or(text(kept, "head")),
        plural(inline_count, "comment"),
        plural(nits.len(), "nit"),
        elsewhere.len()
    );
    let mut out = BTreeMap::new();
    out.insert("summary", summary);
    out.insert("elsewhere", listed(&elsewhere_lines));
    out.insert("nits", listed(&nits));
    out.insert("verification", listed(&verification));
    out.insert("done_well", listed(&done_well));
    (out, nits, elsewhere)
}

/// A template with its sections in place: a `{{#name}}…{{/name}}` block is
/// kept only when its section says something, and what a section says is
/// never read as the template's.
pub fn rendered(template: &str, sections: &BTreeMap<&str, String>) -> String {
    let filled = |name: &str| {
        sections
            .get(name)
            .is_some_and(|said| !said.trim().is_empty())
    };
    let mut kept = template.to_owned();
    for name in SECTIONS {
        let (open, close) = (format!("{{{{#{name}}}}}"), format!("{{{{/{name}}}}}"));
        while let Some(start) = kept.find(&open) {
            let Some(end) = kept[start..].find(&close).map(|at| start + at) else {
                break;
            };
            let inner = kept[start + open.len()..end].to_owned();
            let instead = if filled(name) { inner } else { String::new() };
            kept.replace_range(start..end + close.len(), &instead);
        }
    }
    let mut out = String::new();
    let mut rest = kept.as_str();
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find("}}") {
            Some(end) if SECTIONS.contains(&&after[..end]) => {
                out.push_str(sections.get(&after[..end]).map_or("", String::as_str));
                rest = &after[end + 2..];
            }
            _ => {
                out.push_str("{{");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    while out.contains("\n\n\n") {
        out = out.replace("\n\n\n", "\n\n");
    }
    format!("{}\n", out.trim())
}

/// The template a destination's general comment is written in: the
/// project's `.devpit/devflow/reviewers/publish/<destination>.md`, then each
/// team layer's `reviewers/publish/`, then the person's, then devpit's.
pub fn template(
    root: &Path,
    elsewhere: Personas,
    destination: Destination,
) -> Result<String, String> {
    let file = format!("publish/{}.md", destination.word());
    let project = format!("{}/reviewers/{file}", crate::folder::DIR);
    if let Some(text) = review::text_in(root, &project, MOST_TEMPLATE, "template")? {
        return Ok(text);
    }
    let in_layer = format!("reviewers/{file}");
    for team in elsewhere.teams {
        if let Some(text) = team.read(&in_layer)? {
            if text.len() as u64 > MOST_TEMPLATE {
                return Err(format!(
                    "{}'s {in_layer} is larger than any template needs",
                    team.name
                ));
            }
            return Ok(text);
        }
    }
    if let Some(personal) = elsewhere.personal {
        if let Some(text) = review::text_in(personal, &file, MOST_TEMPLATE, "template")? {
            return Ok(text);
        }
    }
    Ok(destination.shipped().to_owned())
}

/// `publish.json`: a review's findings as its pull request is told them.
pub fn draft(kept: &Value, asked: &Asked, template: &str, verify: Verify) -> Value {
    let list = kept["findings"].as_array().map_or(&[][..], Vec::as_slice);
    let said: Vec<&Value> = list
        .iter()
        .filter(|finding| said_on_pr(finding, verify))
        .collect();
    // One comment per line, whatever its axes.
    let mut lines: BTreeMap<(String, u64), Vec<usize>> = BTreeMap::new();
    for (at, finding) in list.iter().enumerate() {
        if said_on_pr(finding, verify) && inline(finding) {
            lines
                .entry((text(finding, "file").to_owned(), line_of(finding)))
                .or_default()
                .push(at);
        }
    }
    let inline: Vec<Value> = lines
        .iter()
        .map(|((file, line), places)| {
            let axes: Vec<&str> = AXES
                .iter()
                .copied()
                .filter(|axis| places.iter().any(|at| text(&list[*at], "axis") == *axis))
                .collect();
            let body = places
                .iter()
                .map(|at| inline_said(&list[*at], verify))
                .collect::<Vec<_>>()
                .join("\n\n");
            json!({ "file": file, "line": line, "axes": axes, "findings": places, "body": body })
        })
        .collect();
    let (mut sections, nits, elsewhere) = sections(kept, &said, inline.len(), verify);
    let retro = kept["mode"] == "retro";
    let tickets: Vec<Value> = said
        .iter()
        .filter(|finding| retro && ticketed(finding))
        .map(|finding| ticket_of(finding, verify))
        .collect();
    if retro {
        let listed: Vec<String> = tickets
            .iter()
            .enumerate()
            .map(|(at, one)| {
                let impact = one["impact"].as_str().map_or(String::new(), |impact| {
                    format!(" — impact: `{}`", short(impact))
                });
                format!(
                    "{}. **{}** `{}:{}` {}{impact}",
                    at + 1,
                    text(one, "severity"),
                    text(one, "file"),
                    line_of(one),
                    short(text(one, "title"))
                )
            })
            .collect();
        sections.insert("tickets", listed.join("\n"));
        if let Some(summary) = sections.get_mut("summary") {
            summary.push_str(&format!(
                " Already in production, so it is followed up: {} ticket{}.",
                tickets.len(),
                if tickets.len() == 1 { "" } else { "s" }
            ));
        }
    }
    let review_body = format!(
        "devpit review: {} on the lines; the rest is in the comment below.",
        match inline.len() {
            1 => "1 comment".to_owned(),
            count => format!("{count} comments"),
        }
    );
    let mut drafted = json!({
        "version": 1,
        "review": asked.review(),
        "destination": asked.destination.word(),
        "event": asked.event.word(),
        "base": kept["base"],
        "head": kept["head"],
        "verdict": kept["verdict"],
        "review_body": review_body,
        "inline": inline,
        "general": {
            "nits": nits,
            "elsewhere": elsewhere,
            "body": rendered(template, &sections),
        },
    });
    if retro {
        drafted["mode"] = json!("retro");
        drafted["tickets"] = json!(tickets);
    }
    drafted
}

/// An inline comment as the host takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inline {
    pub file: String,
    pub line: u64,
    pub body: String,
}

/// A pull request a review is published on.
pub trait Host {
    /// One review of `event` at `commit`, with `comments` on their lines:
    /// each comment's id, in their order.
    fn review(
        &self,
        commit: &str,
        event: Event,
        body: &str,
        comments: &[Inline],
    ) -> Result<Vec<u64>, String>;
    fn edit_inline(&self, id: u64, body: &str) -> Result<(), String>;
    /// The general comment: its id.
    fn comment(&self, body: &str) -> Result<u64, String>;
    fn edit_comment(&self, id: u64, body: &str) -> Result<(), String>;
}

fn read_json(folder: &Path, file: &str) -> Option<Value> {
    let text = std::fs::read_to_string(folder.join(file)).ok()?;
    serde_json::from_str(&text).ok()
}

fn write(folder: &Path, file: &str, value: &Value) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).unwrap_or_default();
    std::fs::write(folder.join(file), text).map_err(|err| format!("{file}: {err}"))
}

/// The draft posted: a line published before is edited where it changed,
/// a new one joins a new review, and the general comment is edited once it
/// exists. Each id is kept in `published.json` as soon as the host answers.
pub fn published(folder: &Path, draft: &Value, host: &dyn Host) -> Result<Value, String> {
    let mut kept = read_json(folder, PUBLISHED)
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({ "version": 1, "inline": [] }));
    kept["destination"] = draft["destination"].clone();
    if !kept["inline"].is_array() {
        kept["inline"] = json!([]);
    }
    let event = Event::of(text(draft, "event")).unwrap_or(Event::Comment);
    let mut edited = 0;
    let mut new = Vec::new();
    let drafted = draft["inline"].as_array().map_or(&[][..], Vec::as_slice);
    for one in drafted {
        let (file, line, body) = (text(one, "file"), line_of(one), text(one, "body"));
        let had = kept["inline"].as_array_mut().and_then(|list| {
            list.iter_mut()
                .find(|had| text(had, "file") == file && line_of(had) == line)
        });
        match had {
            Some(had) if text(had, "body") == body => {}
            Some(had) => {
                let id = had["id"]
                    .as_u64()
                    .ok_or("published.json lost a comment's id")?;
                host.edit_inline(id, body)?;
                had["body"] = json!(body);
                edited += 1;
                write(folder, PUBLISHED, &kept)?;
            }
            None => new.push(Inline {
                file: file.to_owned(),
                line,
                body: body.to_owned(),
            }),
        }
    }
    let left: Vec<String> = kept["inline"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|had| {
            !drafted
                .iter()
                .any(|one| text(one, "file") == text(had, "file") && line_of(one) == line_of(had))
        })
        .map(|had| format!("{}:{}", text(had, "file"), line_of(had)))
        .collect();
    if !new.is_empty() || event != Event::Comment {
        let ids = host.review(text(draft, "head"), event, text(draft, "review_body"), &new)?;
        if ids.len() != new.len() {
            return Err(format!(
                "the review was posted, but the host named {} of its {} comments: edit them by hand",
                ids.len(),
                new.len()
            ));
        }
        if let Some(list) = kept["inline"].as_array_mut() {
            for (one, id) in new.iter().zip(ids) {
                list.push(
                    json!({ "file": one.file, "line": one.line, "id": id, "body": one.body }),
                );
            }
        }
        write(folder, PUBLISHED, &kept)?;
    }
    let body = text(&draft["general"], "body");
    let general = match kept["general"]["id"].as_u64() {
        Some(_) if text(&kept["general"], "body") == body => "unchanged",
        Some(id) => {
            host.edit_comment(id, body)?;
            "edited"
        }
        None => {
            kept["general"] = json!({ "id": host.comment(body)? });
            "posted"
        }
    };
    kept["general"]["body"] = json!(body);
    write(folder, PUBLISHED, &kept)?;
    Ok(json!({
        "posted": new.len(),
        "edited": edited,
        "general": general,
        "left": left,
    }))
}

/// What a review's run answers the tool: its draft, written for the person
/// to see; and with `apply`, after their yes, that same draft published. A
/// draft that is not the one last shown becomes the one to show instead.
/// `host` is where it would be posted, or why it cannot be.
pub fn respond(
    folder: &Path,
    asked: &Asked,
    template: &str,
    verify: Verify,
    host: Result<&dyn Host, &str>,
) -> Result<Value, String> {
    let kept = read_json(folder, review::FINDINGS).ok_or_else(|| {
        format!(
            "review {} has no findings.json yet: finish it with devpit_devflow_review first",
            asked.review()
        )
    })?;
    let pending: Vec<&str> = kept["pending"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if !pending.is_empty() {
        return Err(format!(
            "review {} is not done: {} still pending",
            asked.review(),
            pending.join(", ")
        ));
    }
    if kept["mode"] == "retro" && asked.event == Event::RequestChanges {
        return Err("a retro review never requests changes: its code is already in production, so it is followed up with its tickets".to_owned());
    }
    let drafted = draft(&kept, asked, template, verify);
    let at = folder.join(DRAFT).display().to_string();
    // The yes was to the draft the person saw: only that one is posted.
    if asked.apply && read_json(folder, DRAFT).as_ref() == Some(&drafted) {
        let mut said = published(folder, &drafted, host?)?;
        said["applied"] = json!(true);
        said["review"] = json!(asked.review());
        said["draft"] = json!(at);
        return Ok(said);
    }
    write(folder, DRAFT, &drafted)?;
    let note = if asked.apply {
        "Nothing was published: the person has not seen this draft, so it is now the one to show. Show it, and apply once they say yes to it."
    } else {
        "Nothing was published. Show the person the draft — each inline comment and the general one — and, only after their explicit yes, call again with apply: true."
    };
    let mut said = Map::new();
    said.insert("applied".to_owned(), json!(false));
    said.insert("review".to_owned(), json!(asked.review()));
    said.insert("draft".to_owned(), json!(at));
    said.insert(
        "inline".to_owned(),
        json!(drafted["inline"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|one| json!({ "at": format!("{}:{}", text(one, "file"), line_of(one)), "body": one["body"] }))
            .collect::<Vec<_>>()),
    );
    said.insert("general".to_owned(), drafted["general"]["body"].clone());
    said.insert("event".to_owned(), drafted["event"].clone());
    if let Err(why) = host {
        said.insert("posts".to_owned(), json!(why));
    }
    said.insert("note".to_owned(), json!(note));
    Ok(Value::Object(said))
}

#[cfg(test)]
#[path = "publish_tests.rs"]
mod tests;
