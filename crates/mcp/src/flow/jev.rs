//! Jev in devflow: one of the flow's rubrics asked of Decisions for a
//! project whose devflow.yaml uses it; the person's labels on the decision
//! log — an item they finished on Jev's word — and the finding rubric held
//! in shadow until those labels show it keeps what the person confirms.
//!
//! The rubrics, their states and what an answer does are the engine's
//! (`devflow_engine::jev`); asking is `crate::decisions`.

use std::path::Path;
use std::sync::Mutex;

use devflow_engine::calibrate::{self, Labelled};
use devflow_engine::config::{Config, Mode, GATE};
use devflow_engine::jev::{self as rules, DevflowDecisions, Said};
use devflow_engine::Ask;
use serde_json::{json, Value};

use crate::decisions::deciding::{self, Asking, Conf, Decided, Skip};
use crate::decisions::log::{Log, Row};
use crate::decisions::rubric::{self, Rubric};
use crate::decisions::settings::Settings;
use crate::project::Project;
use crate::server::Server;

/// The rubric for whether a work item is done, asked once per criterion.
pub const DONE: &str = include_str!("../../../../flow/rubrics/devflow-done.json");
/// More than this is a survey, not a decision.
pub const MOST_QUESTIONS: usize = 20;
/// The most of a rubric file read.
const MOST_RUBRIC_BYTES: u64 = 64 * 1024;

/// `enforce` acts only once the person moved it there in a terminal.
pub fn mode_of(server: &Server, project: &Project, config: &Config) -> Mode {
    if config.decisions.mode == Mode::Enforce && server.consent.made(&project.root, Ask::Enforce) {
        Mode::Enforce
    } else {
        Mode::Shadow
    }
}

/// The Decisions key, when one is set up: never printed, never logged.
pub fn key() -> Option<String> {
    crate::credentials::openrouter_key()
}

/// A project as the decision log names it: its root.
pub fn project_id(project: &Project) -> String {
    project.root.display().to_string()
}

/// A rubric's text read under the name it was asked by.
pub fn rubric_of(name: &str, text: &str) -> Result<Rubric, String> {
    let mut rubric: Rubric = serde_json::from_str(text)
        .map_err(|err| format!("the rubric `{name}` is not one devflow reads: {err}"))?;
    let asked = rubric
        .questions
        .as_object()
        .filter(|asked| !asked.is_empty())
        .ok_or_else(|| format!("the rubric `{name}` asks nothing"))?;
    if asked.len() > MOST_QUESTIONS {
        return Err(format!(
            "the rubric `{name}` asks more than {MOST_QUESTIONS} questions"
        ));
    }
    rubric.name = name.to_owned();
    Ok(rubric)
}

/// A rubric of the project's own, `<folder>/rubrics/<name>.json`.
fn own_rubric(root: &Path, name: &str) -> Result<Option<String>, String> {
    if !devflow_engine::config::is_name(name) {
        return Err("a rubric's name is lowercase letters, digits, - and _".to_owned());
    }
    let relative = format!("{}/{name}.json", rules::dir(root));
    if root.join(&relative).symlink_metadata().is_err() {
        return Ok(None);
    }
    let path = devflow_engine::fsguard::resolve(root, &relative)
        .map_err(|_| format!("the rubric `{name}` leads outside the project"))?;
    let file = std::fs::File::open(path).map_err(|err| err.to_string())?;
    let raw = devflow_engine::fsguard::read_within(file, MOST_RUBRIC_BYTES)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| format!("the rubric `{name}` is larger than any rubric needs"))?;
    String::from_utf8(raw)
        .map(Some)
        .map_err(|_| format!("the rubric `{name}` is not UTF-8 text"))
}

/// One of the flow's rubrics: the project's own, else devflow's —
/// `devflow-done` asked once per criterion.
pub fn rubric(root: &Path, name: &str, criteria: &[String]) -> Result<Rubric, String> {
    if let Some(text) = own_rubric(root, name)? {
        return rubric_of(name, &text);
    }
    if name == GATE {
        return Ok(done_per_criterion(criteria));
    }
    rules::BUILT_IN
        .iter()
        .find(|(built, _)| *built == name)
        .map(|(_, text)| rubric_of(name, text))
        .unwrap_or_else(|| {
            Err(format!(
                "no rubric `{name}`: none in {} and none built in",
                rules::dir(root)
            ))
        })
}

/// `devflow-done` with its `criteriaMet` asked once for each criterion, so a
/// missing one is named rather than averaged away.
pub fn done_per_criterion(criteria: &[String]) -> Rubric {
    let mut done: Rubric = serde_json::from_str(DONE).unwrap_or(Rubric {
        name: String::new(),
        version: None,
        questions: json!({}),
        thresholds: Default::default(),
    });
    let met = done
        .questions
        .get("criteriaMet")
        .cloned()
        .unwrap_or(json!({}));
    let threshold = done.thresholds.remove("criteriaMet");
    let mut questions = done.questions.as_object().cloned().unwrap_or_default();
    questions.remove("criteriaMet");
    for (at, criterion) in criteria
        .iter()
        .take(MOST_QUESTIONS.saturating_sub(questions.len()))
        .enumerate()
    {
        let id = format!("criterion{}", at + 1);
        let mut question = met.clone();
        question["instructions"] = json!(format!(
            "Does the state show this acceptance criterion met, by a test that ran and passed: \"{criterion}\"?"
        ));
        questions.insert(id.clone(), question);
        if let Some(threshold) = threshold {
            done.thresholds.insert(id, threshold);
        }
    }
    done.name = GATE.to_owned();
    done.questions = Value::Object(questions);
    done
}

/// Jev, as one project's flow asks it.
pub struct Jev {
    log: Log,
    conf: Conf,
    project: String,
    item: Option<String>,
    root: std::path::PathBuf,
    mode: Mode,
    criteria: Vec<String>,
    /// This reply's last call: `Some(None)` answered, `Some(Some(why))` not.
    called: Mutex<Option<Option<String>>>,
}

impl Jev {
    /// Jev for this project, wherever devflow.yaml says `use`: without a key,
    /// or opted out, each answer says it was skipped.
    pub fn of(
        server: &Server,
        project: &Project,
        config: &Config,
        item: Option<&str>,
        criteria: &[String],
    ) -> Option<Jev> {
        if !config.decisions.use_ {
            return None;
        }
        let settings = Settings::of_user();
        Some(Jev::with(
            Log::of_user(),
            settings.conf(key()),
            project,
            item,
            mode_of(server, project, config),
            criteria,
        ))
    }

    pub fn with(
        log: Log,
        conf: Conf,
        project: &Project,
        item: Option<&str>,
        mode: Mode,
        criteria: &[String],
    ) -> Jev {
        let mut conf = conf;
        conf.secrets.extend(conf.key.clone());
        Jev {
            log,
            conf,
            project: project_id(project),
            item: item.map(str::to_owned),
            root: project.root.clone(),
            mode,
            criteria: criteria.to_vec(),
            called: Mutex::new(None),
        }
    }

    fn opted_out(&self) -> bool {
        self.conf.opted_out.contains(&self.project)
    }

    /// Where Decisions stands after this reply's calls: the last of them,
    /// or the project's last before it when none was made.
    pub fn state(&self) -> DevflowDecisions {
        let called = self.called.lock().ok().and_then(|called| called.clone());
        let failed = called.unwrap_or_else(|| self.log.failed_last(&self.project));
        rules::decisions_state(
            true,
            self.opted_out(),
            self.conf.key.is_some(),
            failed.as_deref(),
        )
    }

    fn called(&self, failed: Option<String>) {
        if let Ok(mut called) = self.called.lock() {
            *called = Some(failed);
        }
    }

    /// Whether Decisions can answer at all: a key, the project not opted out.
    pub fn answers(&self) -> bool {
        self.conf.key.is_some() && !self.opted_out()
    }

    /// The mode `name` is asked in: the finding rubric, which sets findings
    /// aside, acts only once the person's labels show it keeps the ones they
    /// confirm.
    fn mode_for(&self, name: &str, rubric: &Rubric) -> Mode {
        if self.mode != Mode::Enforce || name != rules::FINDING {
            return self.mode;
        }
        let rows = self.log.of_project(&self.project);
        let rows: Vec<&Row> = rows.iter().collect();
        match enforce_held(&rows, &json!(rubric.thresholds)) {
            None => Mode::Enforce,
            Some(_) => Mode::Shadow,
        }
    }

    /// The rubric `name` asked about `state`, logged under the mode it ran
    /// in, and judged by its thresholds.
    pub fn judge(&self, name: &str, state: &Value) -> Said {
        let skipped = |why: String| {
            self.called(Some(why.clone()));
            Said {
                rubric: name.to_owned(),
                decision: None,
                mode: self.mode,
                outcome: "skipped".to_owned(),
                verdicts: Value::Null,
                answers: Value::Null,
                skipped: Some(why),
            }
        };
        let rubric = match rubric(&self.root, name, &self.criteria) {
            Ok(rubric) => rubric,
            Err(why) => return skipped(why),
        };
        let mode = self.mode_for(name, &rubric);
        let asking = Asking {
            project_id: Some(&self.project),
            card_id: self.item.as_deref(),
            gate: name,
            mode: mode.word(),
            rubric: Some(&rubric),
            state,
            questions: &rubric.questions,
        };
        let (decided, decision) =
            deciding::decide_logged(&self.log, &self.conf, &asking, deciding::now());
        match &decided {
            Decided::Answered { .. } => self.called(None),
            Decided::Skipped(Skip::Off | Skip::OptedOut) => {}
            Decided::Skipped(skip) => self.called(Some(skip.reason())),
        }
        let result = deciding::gated(decided, &rubric, mode.word().to_owned());
        Said {
            rubric: name.to_owned(),
            decision,
            mode,
            outcome: result.outcome.to_owned(),
            verdicts: result.verdicts,
            answers: result.answers,
            skipped: result.skipped.map(|skip| skip.reason()),
        }
    }
}

/// Where Decisions stands for a reply, with the Jev it asked, if any.
pub fn decisions_of(config: &Config, jev: Option<&Jev>) -> Value {
    let state = jev.map_or_else(
        || rules::decisions_state(config.decisions.use_, false, key().is_some(), None),
        Jev::state,
    );
    json!(state)
}

/// An item the person finished: the completion rubric's last word on it,
/// unlabelled yet, was right.
pub fn finished(project: &Project, config: &Config, item: &str) {
    let log = Log::of_user();
    let name = rules::rubric_for(config, "completion").unwrap_or_else(|| GATE.to_owned());
    if let Some(last) = log
        .of_item(item, &name)
        .into_iter()
        .find(|row| row.project.as_deref() == Some(project_id(project).as_str()))
        .filter(|row| row.person_verdict.is_none())
    {
        let _ = log.label(&last.id, true, "finished");
    }
}

/// What a decision's passing turned on: the lowest answer among its yes/no
/// questions held to a `min`.
pub fn score_of(answers: &Value, thresholds: &Value) -> Option<f64> {
    thresholds
        .as_object()?
        .iter()
        .filter(|(_, threshold)| threshold.get("min").is_some_and(Value::is_number))
        .filter_map(|(id, _)| {
            let answer = answers.get(id)?;
            answer
                .get("choice")
                .is_none()
                .then(|| rubric::scalar(answer))
                .flatten()
        })
        .reduce(f64::min)
}

fn parsed(text: Option<&str>) -> Value {
    text.and_then(|text| serde_json::from_str(text).ok())
        .unwrap_or(Value::Null)
}

/// Each decision the person labelled, as calibration reads it.
fn labelled_of(rows: &[&Row]) -> Vec<Labelled> {
    rows.iter()
        .filter_map(|row| {
            Some(Labelled {
                score: score_of(
                    &parsed(row.answers.as_deref()),
                    &parsed(row.thresholds.as_deref()),
                ),
                outcome: row.outcome.clone(),
                truth: row.person_verdict.as_deref()? == "pass",
            })
        })
        .collect()
}

/// Why the finding rubric may not act yet, from the decisions judged by
/// `thresholds`: what an older version failed says nothing of this one.
pub fn enforce_held(rows: &[&Row], thresholds: &Value) -> Option<String> {
    let judged: Vec<&Row> = rows
        .iter()
        .copied()
        .filter(|row| {
            row.rubric.as_deref() == Some(rules::FINDING)
                && parsed(row.thresholds.as_deref()) == *thresholds
        })
        .collect();
    calibrate::enforceable(&labelled_of(&judged)).err()
}

#[cfg(test)]
#[path = "jev_tests.rs"]
mod tests;
