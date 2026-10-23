//! `gate`: whether a card's work may be called done. Its
//! checks ran after the last change and passed, every criterion it lists has
//! a test that passed or a proof file, the evidence it asked for is there,
//! and the review blocks nothing (an evidence or doc card with no code needs
//! none); then, where Decisions is set up, the `devflow-done`
//! rubric. At the end of an agent's turn it also says whether the turn may
//! end, without ever sending it back forever.
//!
//! Pure: the app reads the run, the review and the checkout, asks Decisions
//! and keeps each session's streak; this decides.

use serde_json::{json, Value};

use crate::config::{Config, Evidence as Kept, Mode};
use crate::evidence::plain;
use crate::plan::PREFIX;

/// The fields the tool takes: the card from an agent, the rest from devpit's
/// own hooks (`project` is an orchestrator's, as on every board tool).
pub const FIELDS: [&str; 9] = [
    "card",
    "kind",
    "event",
    "session",
    "stop_hook_active",
    "agent",
    "transcript",
    "pane",
    "cap",
];

/// How many stops in a row the gate sends back before it only warns:
/// Claude Code's own default.
pub const CAP: usize = 8;
/// Where Claude Code reads its own cap, which the gate then follows.
pub const CAP_ENV: &str = "CLAUDE_CODE_STOP_HOOK_BLOCK_CAP";
/// A cap past this is a loop with a number on it.
const MOST_CAP: usize = 50;
/// The missing items a reason names; the rest are in gate.json.
const NAMED: usize = 6;

/// The cap a session asks for, or [`CAP`].
pub fn cap_of(said: Option<&str>) -> usize {
    said.and_then(|said| said.trim().parse::<usize>().ok())
        .filter(|cap| *cap > 0)
        .map_or(CAP, |cap| cap.min(MOST_CAP))
}

/// The hook events the gate answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Stop,
    SubagentStop,
}

/// A stop, as devpit's own hook passes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hook {
    pub event: Event,
    pub session: Option<String>,
    /// The CLI is already going on because a stop hook sent it back.
    pub continued: bool,
    pub agent: Option<String>,
    /// The subagent's transcript, which says when it began.
    pub transcript: Option<String>,
    pub pane: Option<String>,
    pub cap: usize,
}

/// What the tool was asked: a card to judge, or a stop to answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    pub card: Option<String>,
    /// The card's kind when the agent says it, over its body's `Kind:` line.
    pub kind: Option<String>,
    pub hook: Option<Hook>,
}

/// The kinds of card whose deliverable is its proofs, not code.
const PROOF_KINDS: [&str; 2] = ["evidence", "doc"];

/// Whether a card is evidence or a doc: `kind` when the gate was told it,
/// else a `Kind: evidence` or `Kind: doc` line of its body.
pub fn proof_only(body: &str, kind: Option<&str>) -> bool {
    let said = kind.map(str::to_owned).or_else(|| {
        body.lines().find_map(|line| {
            let line = line
                .trim()
                .trim_start_matches(['-', '*', ' '])
                .replace("**", "");
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case("kind")
                .then(|| value.trim().to_owned())
        })
    });
    said.is_some_and(|said| PROOF_KINDS.contains(&said.to_ascii_lowercase().as_str()))
}

/// What an evidence or doc card may commit and still have no code to review.
const NOT_CODE: [&str; 12] = [
    "md", "txt", "pdf", "png", "jpg", "jpeg", "gif", "webp", "avif", "mp4", "webm", "mov",
];

/// Whether a branch's changed files are only docs and pictures: an empty
/// diff is, and anything else, a script or a spec included, is code.
pub fn changed_no_code(files: &[String]) -> bool {
    files.iter().all(|file| {
        std::path::Path::new(file)
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| NOT_CODE.contains(&ext.to_ascii_lowercase().as_str()))
    })
}

/// A text a hook filled in: a placeholder its CLI left as written, or
/// nothing at all, is no value.
fn filled(value: Option<&Value>) -> Option<String> {
    let text = match value? {
        Value::String(text) => text.trim().to_owned(),
        Value::Number(number) => number.to_string(),
        _ => return None,
    };
    (!text.is_empty() && !text.contains("${")).then_some(text)
}

/// The tool's input, refused with what it takes when it is not that.
pub fn asked(params: &Value) -> Result<Asked, String> {
    let fields = params
        .as_object()
        .ok_or("the gate takes { card } from an agent")?;
    if let Some(extra) = fields
        .keys()
        .find(|key| !FIELDS.contains(&key.as_str()) && key.as_str() != "project")
    {
        return Err(format!(
            "`{extra}` is not a field of the gate: it takes {{ card }}"
        ));
    }
    let card = filled(fields.get("card"));
    let hook = match filled(fields.get("event")).as_deref() {
        None => None,
        Some(word) => Some(Hook {
            event: match word {
                "Stop" => Event::Stop,
                "SubagentStop" => Event::SubagentStop,
                _ => return Err("`event` is Stop or SubagentStop, as a hook sends it".to_owned()),
            },
            session: filled(fields.get("session")),
            continued: matches!(fields.get("stop_hook_active"), Some(Value::Bool(true)))
                || filled(fields.get("stop_hook_active")).as_deref() == Some("true"),
            agent: filled(fields.get("agent")),
            transcript: filled(fields.get("transcript")),
            pane: filled(fields.get("pane")),
            cap: cap_of(filled(fields.get("cap")).as_deref()),
        }),
    };
    if card.is_none() && hook.is_none() {
        return Err("which card? pass its id as `card`".to_owned());
    }
    let kind = filled(fields.get("kind"));
    if kind
        .as_deref()
        .is_some_and(|kind| kind != "code" && !PROOF_KINDS.contains(&kind))
    {
        return Err("`kind` is code, evidence or doc".to_owned());
    }
    Ok(Asked { card, kind, hook })
}

/// A card the plan made, and so the flow's to hold: titled `[devflow] `,
/// and not the brief's epic, whose stages wait on the person's yes.
pub fn gated_card(title: &str) -> bool {
    title.starts_with(PREFIX) && !title.starts_with(&format!("{PREFIX}Brief:"))
}

/// A run's stamp without the count a second run in the same second takes.
fn second(name: &str) -> &str {
    name.split('-').next().unwrap_or(name)
}

/// Whether `later` is a time after `than`, both as runs are named.
fn after(later: &str, than: &str) -> bool {
    second(later) > second(than)
}

/// A subagent is held only for code it changed: a change after it began.
/// One that cannot be placed in time is let go; its session's stop is held.
pub fn subagent_changed(changed: Option<&str>, began: Option<&str>) -> bool {
    matches!((changed, began), (Some(changed), Some(began)) if after(changed, began))
}

/// The newest run of the card's checks, with what it left in evidence.json.
pub struct Run<'a> {
    pub name: &'a str,
    pub evidence: &'a Value,
}

/// The newest review, its findings.json, and when it was written.
pub struct Review<'a> {
    pub at: &'a str,
    pub findings: &'a Value,
}

/// What the gate looks at.
pub struct Looked<'a> {
    pub config: &'a Config,
    pub card: &'a str,
    /// The card's acceptance criteria, as its body lists them.
    pub criteria: &'a [String],
    pub run: Option<Run<'a>>,
    pub review: Option<Review<'a>>,
    /// When the checkout's code last changed, as a run's stamp; `None` when
    /// it cannot be told, and then a green run is enough.
    pub changed: Option<&'a str>,
    /// Each own stage's newest `stage-<name>.json`, by the run it is in.
    pub stages: &'a [(String, Option<(String, Value)>)],
    /// The commit the review read, when code changed between it and `HEAD`:
    /// what was approved is not what would be called done.
    pub unreviewed: Option<&'a str>,
    /// An evidence or doc card whose branch changed no code: there is no
    /// diff to review, so it closes on its proofs.
    pub no_code: bool,
}

/// One criterion and the evidence it has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub criterion: String,
    pub evidence: String,
    pub green: bool,
}

/// What the deterministic checks found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub card: String,
    pub run: Option<String>,
    pub changed: Option<String>,
    pub rows: Vec<Row>,
    /// Each check of the run and how it ended.
    pub checks: Vec<(String, String)>,
    /// The review's verdict and what blocks, when there is a review.
    pub review: Option<String>,
    pub missing: Vec<String>,
    /// Judged as an evidence or doc card with no code.
    pub no_code: bool,
}

fn word<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn list<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// The deterministic half of the gate.
pub fn checked(looked: &Looked) -> Checked {
    let config = looked.config;
    let mut missing = Vec::new();
    let configured = &config.stages.execution.checks;
    if configured.is_empty() {
        missing.push(
            "devflow.yaml configures no checks, so nothing can prove the card: add one with `set` (stages.execution.checks)"
                .to_owned(),
        );
    }
    let mut checks = Vec::new();
    let mut rows = Vec::new();
    match &looked.run {
        None => missing.push(format!(
            "no run of the card's checks yet: call `evidence` with card {} and each criterion's tests (devflow-execution)",
            looked.card
        )),
        Some(run) => {
            if let Some(changed) = looked.changed.filter(|changed| after(changed, run.name)) {
                missing.push(format!(
                    "the code changed after run {} (last change {changed}): run `evidence` again",
                    run.name
                ));
            }
            for check in list(run.evidence, "checks") {
                checks.push((word(check, "name").to_owned(), word(check, "result").to_owned()));
            }
            for wanted in configured {
                match checks.iter().find(|(name, _)| *name == wanted.name) {
                    None => missing.push(format!(
                        "check `{}` did not run in {}: leave `checks` out of `evidence` to run them all",
                        wanted.name, run.name
                    )),
                    // Only a check set to write a report is ever inconclusive: one
                    // set to `report: none` is judged by its exit code.
                    Some((_, result)) if result == "inconclusive" => missing.push(format!(
                        "check `{}` left no {} report devflow reads: write it to $DEVFLOW_REPORT_DIR, or set its report to none so its exit code decides (devflow-setup)",
                        wanted.name,
                        wanted.report.word()
                    )),
                    Some((_, result)) if result != "passed" => missing.push(format!(
                        "check `{}` {result} in {}: fix it (devflow-execution) and run the checks again",
                        wanted.name, run.name
                    )),
                    Some(_) => {}
                }
            }
            visual(config, run, &mut missing);
            rows = looked
                .criteria
                .iter()
                .map(|criterion| row(criterion, run))
                .collect();
            for row in rows.iter().filter(|row| !row.green) {
                missing.push(format!("criterion \"{}\": {}", row.criterion, row.evidence));
            }
        }
    }
    if looked.run.is_none() {
        rows = looked
            .criteria
            .iter()
            .map(|criterion| Row {
                criterion: criterion.clone(),
                evidence: "no run".to_owned(),
                green: false,
            })
            .collect();
    }
    let review = reviewed(looked, &mut missing);
    own_stages(looked, &mut missing);
    Checked {
        card: looked.card.to_owned(),
        run: looked.run.as_ref().map(|run| run.name.to_owned()),
        changed: looked.changed.map(str::to_owned),
        rows,
        checks,
        review,
        missing,
        no_code: looked.no_code,
    }
}

const NO_TEST: &str =
    "names no test: map it to its tests, or a proof file, in `evidence`'s criteria";

/// One criterion against the run: green when evidence.json maps it, on the
/// card, to tests that all passed and a proof file that is there.
fn row(criterion: &str, run: &Run) -> Row {
    let seen = list(run.evidence, "criteria")
        .iter()
        .find(|seen| plain(word(seen, "criterion")) == plain(criterion));
    let Some(seen) = seen else {
        return Row {
            criterion: criterion.to_owned(),
            evidence: NO_TEST.to_owned(),
            green: false,
        };
    };
    let mut tests: Vec<String> = list(seen, "tests")
        .iter()
        .map(|test| format!("`{}` {}", word(test, "test"), word(test, "result")))
        .collect();
    let green = seen.get("green").and_then(Value::as_bool) == Some(true);
    if let Some(proof) = seen.get("proof").filter(|proof| proof.is_object()) {
        let (kind, path) = (word(proof, "kind"), word(proof, "path"));
        tests.push(
            if proof.get("exists").and_then(Value::as_bool) == Some(true) {
                format!("proved by {kind} {path}")
            } else {
                format!("{kind} {path} is not in the run's folder or the checkout")
            },
        );
    }
    Row {
        criterion: criterion.to_owned(),
        evidence: if green {
            format!("{} in run {}", tests.join(", "), run.name)
        } else if tests.is_empty() {
            NO_TEST.to_owned()
        } else {
            format!("{}: make them pass (devflow-execution)", tests.join(", "))
        },
        green,
    }
}

/// Screenshots, when the card has its own E2E spec and a check keeps them:
/// a passing spec with no picture proves nothing a person can see.
fn visual(config: &Config, run: &Run, missing: &mut Vec<String>) {
    let spec = run.evidence.get("spec");
    if spec
        .and_then(|spec| spec.get("exists"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return;
    }
    let keeping: Vec<&str> = config
        .stages
        .execution
        .checks
        .iter()
        .filter(|check| check.evidence.contains(&Kept::Screenshots))
        .map(|check| check.name.as_str())
        .collect();
    let pictures: usize = list(run.evidence, "checks")
        .iter()
        .filter(|check| keeping.contains(&word(check, "name")))
        .map(|check| list(check, "screenshots").len())
        .sum();
    if !keeping.is_empty() && pictures == 0 {
        missing.push(format!(
            "the card's E2E spec {} kept no screenshot: end each of its tests in one (devflow-execution)",
            word(spec.unwrap_or(&Value::Null), "path")
        ));
    }
}

/// Each own stage with a gate: passed, and since the last change to the code.
fn own_stages(looked: &Looked, missing: &mut Vec<String>) {
    for step in looked.config.own_on() {
        if step
            .own
            .as_ref()
            .and_then(|own| own.gate.as_ref())
            .is_none()
        {
            continue;
        }
        let name = step.name();
        let seen = looked
            .stages
            .iter()
            .find(|(stage, _)| stage == name)
            .and_then(|(_, seen)| seen.as_ref());
        match seen {
            None => missing.push(format!(
                "the stage `{name}` ({}) has not passed its gate: follow its skill, then call `stage` with the card",
                step.uses
            )),
            Some((run, record)) if record.get("passed").and_then(Value::as_bool) != Some(true) => {
                missing.push(format!(
                    "the stage `{name}`'s gate failed in {run}: fix what it says and call `stage` again"
                ))
            }
            Some((run, _)) => {
                if let Some(changed) = looked.changed.filter(|changed| after(changed, run)) {
                    missing.push(format!(
                        "the stage `{name}`'s gate passed before the last change ({changed}): call `stage` again"
                    ));
                }
            }
        }
    }
}

/// The review: required where its stage is on, read wherever it exists.
fn reviewed(looked: &Looked, missing: &mut Vec<String>) -> Option<String> {
    let Some(review) = &looked.review else {
        if looked.config.stages.review.enabled && !looked.no_code {
            missing.push(
                "no review yet: run the review stage (devflow-review), which writes findings.json"
                    .to_owned(),
            );
        }
        return None;
    };
    let blocking = crate::findings::blocking(
        list(review.findings, "findings"),
        &looked.config.review.block_on,
        looked.config.review.verify,
    );
    for finding in blocking.iter().take(NAMED) {
        missing.push(format!(
            "finding `{}:{}` {} ({}) is in block_on: fix it (devflow-execution) and review again",
            word(finding, "file"),
            finding
                .get("line")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
            word(finding, "title"),
            word(finding, "severity")
        ));
    }
    let pending: Vec<&str> = list(review.findings, "pending")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    if !pending.is_empty() {
        missing.push(format!(
            "the review has not covered {} yet: review them from its packet and call `review` with its run and your reports (devflow-review)",
            pending.join(", ")
        ));
    }
    if let Some(read) = looked.unreviewed {
        missing.push(format!(
            "the review read {}, and the code changed since: review again (devflow-review)",
            read.get(..12).unwrap_or(read)
        ));
    }
    if let Some(changed) = looked.changed.filter(|changed| after(changed, review.at)) {
        missing.push(format!(
            "the review is older than the last change ({changed}): review again (devflow-review)"
        ));
    }
    Some(format!(
        "verdict {}, {} in block_on",
        match word(review.findings, "verdict") {
            "" => "unsaid",
            verdict => verdict,
        },
        blocking.len()
    ))
}

/// What Decisions said of the `devflow-done` rubric.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judged {
    pub rubric: String,
    pub mode: Mode,
    /// `pass`, `grey`, `fail` or `skipped`.
    pub outcome: String,
    /// Why it was skipped, or the questions that failed.
    pub said: Vec<String>,
}

/// The gate: the checks, and what Decisions said when it was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gate {
    pub checked: Checked,
    pub decisions: Option<Judged>,
    /// When it was run, as a run's stamp.
    pub at: String,
}

impl Gate {
    /// The gate; a failing rubric holds the card only in `enforce`, which
    /// is the person's click. A skip never does: without Decisions the
    /// checks alone decide.
    pub fn new(mut checked: Checked, decisions: Option<Judged>, at: &str) -> Gate {
        if let Some(judged) = decisions
            .as_ref()
            .filter(|judged| judged.mode == Mode::Enforce && judged.outcome == "fail")
        {
            checked.missing.push(format!(
                "Decisions judged {} failing ({}): look again at what it names",
                judged.rubric,
                judged.said.join(", ")
            ));
        }
        Gate {
            checked,
            decisions,
            at: at.to_owned(),
        }
    }

    pub fn passed(&self) -> bool {
        self.checked.missing.is_empty()
    }

    /// The criteria with evidence, of all the card lists.
    pub fn counted(&self) -> (usize, usize) {
        let rows = &self.checked.rows;
        (rows.iter().filter(|row| row.green).count(), rows.len())
    }

    /// The one line the comment starts with.
    pub fn headline(&self) -> String {
        let (with, of) = self.counted();
        format!("{PREFIX}gate: {with} of {of} criteria with evidence")
    }

    /// What tells one failing look from the next: a turn that changed none
    /// of it made no progress.
    pub fn fingerprint(&self) -> String {
        format!(
            "{}|{}|{}",
            self.checked.run.as_deref().unwrap_or_default(),
            self.checked.changed.as_deref().unwrap_or_default(),
            self.checked.missing.join("|")
        )
    }

    /// Why a stop is sent back: short, and what to do about it.
    pub fn reason(&self) -> String {
        let missing = &self.checked.missing;
        let mut said = format!("{} — the card is not done yet:\n", self.headline());
        for item in missing.iter().take(NAMED) {
            said.push_str(&format!("- {item}\n"));
        }
        if missing.len() > NAMED {
            said.push_str(&format!(
                "- and {} more in gate.json\n",
                missing.len() - NAMED
            ));
        }
        said.push_str(
            "Fix what is listed, run `evidence` and call `gate` before \
             saying it is done. If you are stopping for the person's answer instead, ask it and stop.",
        );
        said
    }
}

fn decisions_json(gate: &Gate) -> Value {
    gate.decisions.as_ref().map_or(Value::Null, |judged| {
        json!({
            "rubric": judged.rubric,
            "mode": judged.mode.word(),
            "outcome": judged.outcome,
            "said": judged.said,
        })
    })
}

/// `gate.json`: everything the gate looked at and decided.
pub fn recorded(gate: &Gate) -> Value {
    let (with, of) = gate.counted();
    let checked = &gate.checked;
    json!({
        "card": checked.card,
        "at": gate.at,
        "passed": gate.passed(),
        "run": checked.run,
        "changed": checked.changed,
        "criteria_with_evidence": with,
        "criteria": of,
        "rows": checked.rows.iter().map(|row| json!({
            "criterion": row.criterion, "evidence": row.evidence, "green": row.green,
        })).collect::<Vec<_>>(),
        "checks": checked.checks.iter().map(|(name, result)| json!({ "name": name, "result": result })).collect::<Vec<_>>(),
        "review": checked.review,
        "missing": checked.missing,
        "no_code": checked.no_code,
        "decisions": decisions_json(gate),
    })
}

/// What the agent is answered: passed, or what is missing.
pub fn answer(gate: &Gate, file: Option<&str>) -> Value {
    let (with, of) = gate.counted();
    json!({
        "result": if gate.passed() { "passed" } else { "failed" },
        "criteria": format!("{with} of {of}"),
        "missing": gate.checked.missing,
        "run": gate.checked.run,
        "gate": file,
        "decisions": decisions_json(gate),
        "next": if gate.passed() {
            "Write the handoff note with `handoff`, then `finish`."
        } else {
            "Leave the card where it is: fix what is missing in the stage named, then call the gate again."
        },
    })
}

/// A cell of the comment's table, kept to one line.
fn cell(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

/// The comment devpit signs on the card, in the completion skill's table.
pub fn comment(gate: &Gate) -> String {
    let checked = &gate.checked;
    let fresh = match (&checked.run, &checked.changed) {
        (Some(run), Some(changed)) if after(changed, run) => "no",
        (Some(_), Some(_)) => "yes",
        (Some(_), None) => "unknown",
        (None, _) => "no",
    };
    let mut text = format!(
        "{}\n\n| Claim | Evidence | Fresh |\n|---|---|---|\n",
        gate.headline()
    );
    for row in &checked.rows {
        text.push_str(&format!(
            "| {} | {} | {} |\n",
            cell(&row.criterion),
            cell(&row.evidence),
            if row.green { fresh } else { "no" }
        ));
    }
    let checks: Vec<String> = checked
        .checks
        .iter()
        .map(|(name, result)| format!("`{name}` {result}"))
        .collect();
    text.push_str(&format!(
        "| checks green | {} | {fresh} |\n",
        cell(&if checks.is_empty() {
            "no run".to_owned()
        } else {
            checks.join(", ")
        })
    ));
    if let Some(review) = &checked.review {
        text.push_str(&format!("| review clear | {} | |\n", cell(review)));
    }
    if let Some(judged) = &gate.decisions {
        text.push_str(&format!(
            "| Decisions | {}: {} ({}) | |\n",
            judged.rubric,
            judged.outcome,
            judged.mode.word()
        ));
    }
    if gate.passed() {
        text.push_str("\nPassed.\n");
    } else {
        text.push_str("\nNot done yet:\n");
        for item in &checked.missing {
            text.push_str(&format!("- {item}\n"));
        }
    }
    text
}

/// One session's stops sent back in a row, and what the last one looked like.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Streak {
    pub blocks: usize,
    pub last: Option<String>,
}

/// What a stop is answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Said {
    /// The turn ends.
    Let,
    /// The turn goes on, told why.
    Block(String),
    /// The turn ends with the gate failing, and the person is told.
    Warn(String),
}

/// A stop answered: let go when the gate passed, sent back when it failed,
/// and only warned about once the session has been sent back `cap` times in
/// a row — or sent back and came back with nothing changed, which is a
/// turn waiting on the person, not one making progress. A stop the CLI did
/// not continue starts the count again.
pub fn said(hook: &Hook, streak: &mut Streak, failed: Option<(String, String)>) -> Said {
    if !hook.continued {
        *streak = Streak::default();
    }
    let Some((fingerprint, reason)) = failed else {
        *streak = Streak::default();
        return Said::Let;
    };
    let stuck = hook.continued && streak.last.as_deref() == Some(fingerprint.as_str());
    if streak.blocks >= hook.cap || stuck {
        let sent_back = streak.blocks;
        *streak = Streak::default();
        return Said::Warn(format!(
            "Devflow's gate let this turn end without its evidence, after sending it back {sent_back} time{}. {reason}",
            if sent_back == 1 { "" } else { "s" }
        ));
    }
    streak.blocks += 1;
    streak.last = Some(fingerprint);
    Said::Block(reason)
}

/// The hook's reply, as Claude Code and Codex both read it: nothing lets
/// the turn end, a block sends it on with the reason as its next prompt.
pub fn reply(said: &Said) -> Value {
    match said {
        Said::Let => json!({}),
        Said::Block(reason) => json!({ "decision": "block", "reason": reason }),
        Said::Warn(message) => json!({ "systemMessage": message }),
    }
}

#[cfg(test)]
#[path = "gate_tests.rs"]
mod tests;
