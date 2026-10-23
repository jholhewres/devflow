//! Jev in Devflow: the four rubrics devpit ships with the flow — each one
//! overridable in the project's `.devpit/devflow/rubrics/` — the small state
//! each is asked about, and what an answer does. In `shadow` it is recorded
//! and nothing else; in `enforce`, the person's click, it acts.
//!
//! Never the diff and never a conversation: a finding with its anchor in the
//! diff, the others at its place and the lines its file changed, the criteria with a summary of their
//! evidence, the brief as its fields, the plan as its cards.
//!
//! Pure: asking Decisions is the app's.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::brief::Brief;
use crate::config::{Config, Mode, GATE};
use crate::plan::Slice;

pub const FINDING: &str = "devflow-finding";
pub const BRIEF: &str = "devflow-brief";
pub const PLAN: &str = "devflow-plan";
pub const DONE: &str = GATE;

/// Where a project keeps rubrics of its own, one `<name>.json` each.
pub const DIR: &str = ".devpit/devflow/rubrics";

/// The rubrics devpit ships with Devflow. `devflow-done` is the app's
/// `done`, asked once per criterion.
pub const BUILT_IN: [(&str, &str); 3] = [
    (
        FINDING,
        include_str!("../../../flow/rubrics/devflow-finding.json"),
    ),
    (
        BRIEF,
        include_str!("../../../flow/rubrics/devflow-brief.json"),
    ),
    (
        PLAN,
        include_str!("../../../flow/rubrics/devflow-plan.json"),
    ),
];

/// The stage whose work each rubric judges, as `decisions.rubrics` keys them.
pub const STAGES: [(&str, &str); 4] = [
    ("briefing", BRIEF),
    ("plan", PLAN),
    ("review", FINDING),
    ("completion", DONE),
];

/// Whether Devflow's questions reach Decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionsState {
    On,
    /// `decisions.use` is false, or the project's state is never sent.
    Off,
    NoKey,
    /// The last call came to nothing.
    Failing,
}

/// Where Decisions stands, said the same in every reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevflowDecisions {
    pub state: DecisionsState,
    /// Why it is not `on`.
    pub reason: Option<String>,
}

/// Where Decisions stands for a project's Devflow: off where devflow.yaml or
/// the person's Settings keep its state home, `no_key` without a key,
/// `failing` when the last call came to nothing, else on.
pub fn decisions_state(
    used: bool,
    opted_out: bool,
    key: bool,
    failed: Option<&str>,
) -> DevflowDecisions {
    let (state, reason) = match failed {
        _ if !used => (
            DecisionsState::Off,
            Some("decisions.use is false in devflow.yaml"),
        ),
        _ if opted_out => (
            DecisionsState::Off,
            Some("this project's state is not sent to Decisions — see Settings → Decisions"),
        ),
        _ if !key => (
            DecisionsState::NoKey,
            Some("no key — set one in Settings → Decisions"),
        ),
        Some(why) => (DecisionsState::Failing, Some(why)),
        None => (DecisionsState::On, None),
    };
    DevflowDecisions {
        state,
        reason: reason.map(str::to_owned),
    }
}

/// The rubric `stage`'s work is judged by: the one devflow.yaml names for
/// it, else devpit's.
pub fn rubric_for(config: &Config, stage: &str) -> Option<String> {
    if let Some(named) = config.decisions.rubrics.get(stage) {
        return Some(named.clone());
    }
    if stage == "completion" {
        return Some(config.stages.completion.gate.clone());
    }
    STAGES
        .iter()
        .find(|(one, _)| *one == stage)
        .map(|(_, rubric)| (*rubric).to_owned())
}

/// The most of a state sent, as text: small on purpose.
pub const MOST_STATE: usize = 6_000;
/// A text field of a state, at first; halved until the state fits.
const LONGEST_FIELD: usize = 600;
/// The items of a list a state keeps.
const MOST_ITEMS: usize = 20;
/// The findings one review asks Jev about; the rest are merged as they are.
pub const MOST_FINDINGS: usize = 20;

fn cut(value: &Value, longest: usize) -> Value {
    match value {
        Value::String(text) if text.chars().count() > longest => {
            let mut kept: String = text.chars().take(longest).collect();
            kept.push('…');
            Value::String(kept)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .take(MOST_ITEMS)
                .map(|item| cut(item, longest))
                .collect(),
        ),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, item)| (key.clone(), cut(item, longest)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// `state`, its texts cut until all of it fits in [`MOST_STATE`].
pub fn capped(state: &Value) -> Value {
    let mut longest = LONGEST_FIELD;
    loop {
        let kept = cut(state, longest);
        if kept.to_string().len() <= MOST_STATE || longest <= 40 {
            return kept;
        }
        longest /= 2;
    }
}

/// The new side's line ranges of each file a unified diff changes: what a
/// finding is asked to be inside, without the diff itself.
pub fn changed_lines(diff: &str) -> BTreeMap<String, Vec<(u64, u64)>> {
    crate::findings::diffed(diff)
        .into_iter()
        .filter(|(_, diffed)| !diffed.hunks.is_empty())
        .map(|(file, diffed)| (file, diffed.hunks.into_iter().take(50).collect()))
        .collect()
}

fn texts(value: &Value, keys: &[&str]) -> Value {
    let mut kept = Map::new();
    for key in keys {
        if let Some(item) = value.get(*key).filter(|item| !item.is_null()) {
            kept.insert((*key).to_owned(), item.clone());
        }
    }
    Value::Object(kept)
}

/// What Jev is asked about one finding: the finding with its anchor, a fact
/// devpit read from the diff, the others at its place, the lines its file
/// changed, and the card's criteria.
pub fn finding_state(
    finding: &Value,
    others: &[&Value],
    changed: &[(u64, u64)],
    criteria: &[String],
) -> Value {
    capped(&json!({
        "finding": texts(finding, &[
            "file", "line", "end_line", "anchor", "axis", "severity", "title", "description",
            "evidence", "poc", "suggestion",
        ]),
        "others_here": others.iter().map(|other| texts(other, &[
            "line", "end_line", "severity", "title", "description",
        ])).collect::<Vec<_>>(),
        "changed": changed.iter().map(|(from, to)| format!("{from}-{to}")).collect::<Vec<_>>(),
        "criteria": criteria,
    }))
}

/// What Jev is asked about a brief: its fields, as the epic says them.
pub fn brief_state(title: &str, brief: &Brief) -> Value {
    capped(&json!({
        "epic": title,
        "goal": brief.goal,
        "for_whom": brief.for_whom,
        "success": brief.success,
        "out_of_scope": brief.out_of_scope,
        "constraints": brief.constraints,
        "decisions": brief.decisions,
    }))
}

/// What Jev is asked about a plan: its cards, by what each builds and checks.
pub fn plan_state(slices: &[Slice]) -> Value {
    capped(&json!({
        "cards": slices.iter().map(|slice| json!({
            "key": slice.key,
            "title": slice.title,
            "build": slice.build,
            "criteria": slice.criteria,
            "verify": slice.verify,
            "depends_on": slice.depends_on,
        })).collect::<Vec<_>>(),
    }))
}

/// What Jev said of one thing.
#[derive(Debug, Clone, PartialEq)]
pub struct Said {
    pub rubric: String,
    /// The decision log's row, when Decisions was asked.
    pub decision: Option<String>,
    pub mode: Mode,
    /// `pass`, `grey`, `fail` or `skipped`.
    pub outcome: String,
    /// Per question: `{ verdict, value }`.
    pub verdicts: Value,
    /// Per question, as Jev answered it.
    pub answers: Value,
    /// Why nothing was asked, or nothing answered.
    pub skipped: Option<String>,
}

impl Said {
    pub fn verdict(&self, question: &str) -> Option<&str> {
        self.verdicts.get(question)?.get("verdict")?.as_str()
    }

    pub fn value(&self, question: &str) -> Option<f64> {
        self.verdicts.get(question)?.get("value")?.as_f64()
    }

    pub fn choice(&self, question: &str) -> Option<&str> {
        self.answers.get(question)?.get("choice")?.as_str()
    }

    /// The questions it failed.
    pub fn failing(&self) -> Vec<String> {
        self.verdicts
            .as_object()
            .map(|verdicts| {
                verdicts
                    .iter()
                    .filter(|(_, verdict)| verdict["verdict"] == "fail")
                    .map(|(id, _)| id.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Whether it acts: in `enforce`, and only on an answer.
    pub fn acts(&self) -> bool {
        self.mode == Mode::Enforce && self.skipped.is_none()
    }

    pub fn to_json(&self) -> Value {
        json!({
            "rubric": self.rubric, "decision": self.decision, "mode": self.mode.word(),
            "outcome": self.outcome, "verdicts": self.verdicts, "answers": self.answers,
            "skipped": self.skipped,
        })
    }

    pub fn of(value: &Value) -> Option<Said> {
        Some(Said {
            rubric: value.get("rubric")?.as_str()?.to_owned(),
            decision: value["decision"].as_str().map(str::to_owned),
            mode: if value["mode"] == "enforce" {
                Mode::Enforce
            } else {
                Mode::Shadow
            },
            outcome: value.get("outcome")?.as_str()?.to_owned(),
            verdicts: value["verdicts"].clone(),
            answers: value["answers"].clone(),
            skipped: value["skipped"].as_str().map(str::to_owned),
        })
    }
}

/// A finding's key across the consolidations of one review: who said what
/// where.
pub fn finding_key(finding: &Value) -> String {
    ["agent", "persona", "file", "line", "axis", "title"]
        .iter()
        .map(|key| match &finding[*key] {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        })
        .collect::<Vec<_>>()
        .join("|")
}

/// Whether a finding is in the diff, from its anchor: `None` without one.
pub fn in_diff(finding: &Value) -> Option<bool> {
    match finding["anchor"].as_str()? {
        "added" | "context" => Some(true),
        _ => Some(false),
    }
}

/// Two severities one step apart: within the band an adjacent threshold
/// passes, so neither is sure enough to replace the other.
fn neighbours(one: &str, other: &str) -> bool {
    let at = |word: &str| {
        crate::config::Severity::ALL
            .iter()
            .position(|one| one.word() == word)
    };
    matches!((at(one), at(other)), (Some(one), Some(other)) if one.abs_diff(other) == 1)
}

/// Jev's word on a finding, kept on it as `jev`. Acting, a finding that is
/// not real is set aside and holds nothing, and a severity Jev is sure of
/// replaces the reviewer's when more than a step from it — never raised to
/// critical or high without the PoC those need. Whether it is in the diff
/// is the anchor's, and sets nothing aside: a missing test or a caller the
/// change broke sits outside the hunks.
pub fn on_finding(finding: &mut Value, said: &Said) {
    let mut jev = json!({
        "decision": said.decision,
        "mode": said.mode.word(),
        "outcome": said.outcome,
        "real": said.value("real"),
        "severity": said.choice("severity"),
        "duplicate": said.value("duplicate"),
        "in_diff": in_diff(finding),
    });
    if let Some(skipped) = &said.skipped {
        jev["skipped"] = json!(skipped);
    }
    let mut acted: Vec<String> = Vec::new();
    if said.acts() {
        if said.verdict("real") == Some("fail") {
            acted.push("set aside: not a real problem".to_owned());
        }
        if !acted.is_empty() {
            jev["set_aside"] = json!(true);
        }
        let now = finding["severity"].as_str().unwrap_or_default().to_owned();
        let has_poc = finding["poc"]
            .as_str()
            .is_some_and(|poc| !poc.trim().is_empty());
        let sure = said.verdict("severity") == Some("pass");
        if let Some(chosen) = said.choice("severity").filter(|chosen| {
            sure && *chosen != now
                && !neighbours(chosen, &now)
                && crate::findings::severity_of(chosen).is_some()
                && (has_poc || !matches!(*chosen, "critical" | "high"))
        }) {
            acted.push(format!("severity {now} → {chosen}"));
            finding["severity"] = json!(chosen);
        }
    }
    if !acted.is_empty() {
        jev["acted"] = json!(acted);
    }
    finding["jev"] = jev;
}

/// Whether Jev, acting, called a finding the same problem as one at its place.
pub fn duplicate(said: &Said) -> bool {
    said.acts() && said.verdict("duplicate") == Some("fail")
}

/// Why Jev holds a brief or a plan: acting, and the questions it failed.
pub fn holds(said: &Said) -> Option<String> {
    (said.acts() && said.outcome == "fail").then(|| {
        format!(
            "Jev judged it failing on {} ({})",
            said.failing().join(", "),
            said.rubric
        )
    })
}

#[cfg(test)]
#[path = "jev_tests.rs"]
mod tests;
