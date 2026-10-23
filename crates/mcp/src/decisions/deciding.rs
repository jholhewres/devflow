//! Asking Decisions: Jev, TypeSafe AI's "System One" model, through
//! OpenRouter. It writes no text — given a state and typed questions it
//! answers each with a calibrated probability, a distribution or a score.
//!
//! Optional everywhere it is used. Without a key, with the project opted out,
//! over the day's cap or with the provider unreachable, the answer is
//! [`Decided::Skipped`] and the caller does what it did without Decisions.

use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::log::{Log, Row};
use super::rubric::{judged, Rubric};

/// About 32k tokens of state. Past it the state is cut, and the answer says so.
pub const MOST_STATE: usize = 100_000;

/// A decision is a gate in someone's flow; a slow one is a skipped one.
const WAIT: Duration = Duration::from_secs(5);

/// The most of a reply read from the provider.
const MOST_REPLY: usize = 512 * 1024;

/// What a decision needs that the settings hold.
#[derive(Debug, Clone, Default)]
pub struct Conf {
    pub base: String,
    pub model: String,
    pub cap_usd: f64,
    /// None is Decisions off.
    pub key: Option<String>,
    pub opted_out: Vec<String>,
    /// Values taken out of the state before it leaves the machine.
    pub secrets: Vec<String>,
}

/// One question to ask.
pub struct Asking<'a> {
    pub project_id: Option<&'a str>,
    pub card_id: Option<&'a str>,
    pub gate: &'a str,
    /// The mode the flow asks it in.
    pub mode: &'a str,
    pub rubric: Option<&'a Rubric>,
    pub state: &'a Value,
    pub questions: &'a Value,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Decided {
    Answered {
        answers: Value,
        cost_usd: f64,
        latency_ms: u64,
        truncated: bool,
    },
    Skipped(Skip),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Skip {
    /// No key: Decisions was never set up.
    Off,
    OptedOut,
    Budget,
    Failed(String),
}

impl Skip {
    pub fn reason(&self) -> String {
        match self {
            Self::Off => "Decisions is off — set it up with `devflow jev setup`".to_owned(),
            Self::OptedOut => {
                "this project's state is not sent to Decisions — see `devflow jev setup`".to_owned()
            }
            Self::Budget => {
                "today's Decisions budget is spent — raise it with `devflow jev setup`".to_owned()
            }
            Self::Failed(why) => why.clone(),
        }
    }
}

/// What a gate decided: the worst verdict of its rubric, or `skipped`.
#[derive(Debug, Clone, PartialEq)]
pub struct GateResult {
    pub outcome: &'static str,
    pub answers: Value,
    pub verdicts: Value,
    pub mode: String,
    pub cost_usd: f64,
    pub latency_ms: u64,
    pub truncated: bool,
    pub skipped: Option<Skip>,
}

/// What a decision came to, as a gate reads it.
pub fn gated(decided: Decided, rubric: &Rubric, mode: String) -> GateResult {
    match decided {
        Decided::Answered {
            answers,
            cost_usd,
            latency_ms,
            truncated,
        } => {
            let (outcome, verdicts) = judged(rubric, &answers);
            GateResult {
                outcome: outcome.as_str(),
                answers: readable(&answers),
                verdicts,
                mode,
                cost_usd,
                latency_ms,
                truncated,
                skipped: None,
            }
        }
        Decided::Skipped(skip) => GateResult {
            outcome: "skipped",
            answers: Value::Null,
            verdicts: Value::Null,
            mode,
            cost_usd: 0.0,
            latency_ms: 0,
            truncated: false,
            skipped: Some(skip),
        },
    }
}

/// Asks once, without retrying, and logs what came of it, answering the
/// log's row: what a person's label on it later names. Nothing is sent
/// without a key, for a project opted out or past the day's cap; those
/// skips are not logged, because nothing was decided.
pub fn decide_logged(
    log: &Log,
    conf: &Conf,
    asking: &Asking<'_>,
    now: i64,
) -> (Decided, Option<String>) {
    let Some(key) = conf.key.as_deref() else {
        return (Decided::Skipped(Skip::Off), None);
    };
    if asking
        .project_id
        .is_some_and(|id| conf.opted_out.iter().any(|out| out == id))
    {
        return (Decided::Skipped(Skip::OptedOut), None);
    }
    let spent = log.spend_since(today(now));
    if spent >= conf.cap_usd {
        return (Decided::Skipped(Skip::Budget), None);
    }
    let (state, truncated) = prepared(asking.state, &conf.secrets);
    let questions = match wire_questions(asking.questions) {
        Ok(questions) => questions,
        Err(why) => return (Decided::Skipped(Skip::Failed(why)), None),
    };
    let began = Instant::now();
    let called = call(&conf.base, &conf.model, key, &state, &questions);
    let latency_ms = began.elapsed().as_millis() as u64;
    let decided = match called {
        Ok((answers, cost_usd)) => Decided::Answered {
            answers,
            cost_usd,
            latency_ms,
            truncated,
        },
        Err(why) => Decided::Skipped(Skip::Failed(why)),
    };
    let (outcome, answers, cost_usd) = match &decided {
        Decided::Answered {
            answers, cost_usd, ..
        } => (
            asking
                .rubric
                .map_or("answered", |rubric| judged(rubric, answers).0.as_str()),
            Some(answers.to_string()),
            *cost_usd,
        ),
        Decided::Skipped(_) => ("skipped", None, 0.0),
    };
    let thresholds = asking
        .rubric
        .map(|rubric| json!(rubric.thresholds).to_string());
    let failure = match &decided {
        Decided::Skipped(Skip::Failed(why)) => Some(why.as_str()),
        _ => None,
    };
    let logged = log.write(Row {
        id: String::new(),
        at: now,
        project: asking.project_id.map(str::to_owned),
        item: asking.card_id.map(str::to_owned),
        gate: asking.gate.to_owned(),
        mode: asking.mode.to_owned(),
        rubric: asking.rubric.map(|rubric| rubric.name.clone()),
        rubric_version: asking.rubric.and_then(|rubric| rubric.version.clone()),
        questions: questions.to_string(),
        answers,
        thresholds,
        outcome: outcome.to_owned(),
        cost_usd,
        latency_ms: latency_ms as i64,
        state_digest: digest(&state),
        failure: failure.map(str::to_owned),
        person_verdict: None,
        person_action: None,
    });
    (decided, logged.ok())
}

/// The state as sent: text, with every secret devflow knows taken out, then cut
/// to [`MOST_STATE`] — in that order, so a cut cannot leave half a secret the
/// redaction no longer recognises.
pub fn prepared(state: &Value, secrets: &[String]) -> (String, bool) {
    let text = match state {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    let clean = secrets
        .iter()
        .filter(|secret| secret.len() >= 8)
        .fold(text, |text, secret| {
            text.replace(secret.as_str(), "[hidden by devflow]")
        });
    if clean.chars().count() <= MOST_STATE {
        return (clean, false);
    }
    (clean.chars().take(MOST_STATE).collect(), true)
}

/// The questions as the wire names them: assay's `boolean` is `noul` there.
pub fn wire_questions(questions: &Value) -> Result<Value, String> {
    let asked = questions
        .as_object()
        .filter(|asked| !asked.is_empty())
        .ok_or("questions are an object of question id to question")?;
    let mut wire = serde_json::Map::new();
    for (id, question) in asked {
        let mut question = question.clone();
        let kind = question.get("type").and_then(Value::as_str).unwrap_or("");
        let kind = match kind {
            "boolean" | "noul" => "noul",
            "choice" | "score" => kind,
            _ => return Err(format!("question `{id}` is noul, choice or score")),
        };
        if kind == "choice" {
            if let Some(gap) = unexplained_choice(&question) {
                return Err(format!(
                    "choice question `{id}` needs criteria saying what each option means: {gap}"
                ));
            }
        }
        question["type"] = json!(kind);
        wire.insert(id.clone(), question);
    }
    Ok(Value::Object(wire))
}

/// What a choice question leaves unsaid: no criteria, or an option they do
/// not explain. Decisions refuses such a question with a 400, on every call.
fn unexplained_choice(question: &Value) -> Option<String> {
    let Some(criteria) = question.get("criteria").and_then(Value::as_object) else {
        return Some("it has no criteria".to_owned());
    };
    let options = question.get("options").and_then(Value::as_array)?;
    options
        .iter()
        .map(|option| {
            option
                .as_str()
                .map_or_else(|| option.to_string(), str::to_owned)
        })
        .find(|option| {
            criteria
                .get(option)
                .and_then(Value::as_str)
                .is_none_or(|meaning| meaning.trim().is_empty())
        })
        .map(|option| format!("`{option}` has none"))
}

/// The answers with a noul's probability under a name an agent reads.
pub fn readable(answers: &Value) -> Value {
    let mut answers = answers.clone();
    if let Some(each) = answers.as_object_mut() {
        for answer in each.values_mut() {
            if let Some(p) = answer.get("noul").cloned() {
                answer["probability"] = p;
            }
        }
    }
    answers
}

/// A hash and a length: enough to tell two states apart, nothing to read.
pub fn digest(state: &str) -> String {
    let hash = Sha256::digest(state.as_bytes());
    let hex: String = hash.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("{hex}:{}", state.chars().count())
}

/// One request to the provider's System One endpoint: the answers, and what
/// it cost.
pub fn call(
    base: &str,
    model: &str,
    key: &str,
    state: &str,
    questions: &Value,
) -> Result<(Value, f64), String> {
    // Every call: no retention and no training, whatever the account says.
    let body = json!({
        "model": model,
        "state": state,
        "questions": questions,
        "provider": { "zdr": true, "data_collection": "deny" },
    });
    let url = format!("{}/systemone", base.trim_end_matches('/'));
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(WAIT))
        .http_status_as_error(false)
        .user_agent(concat!("devflow/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    let mut reply = agent
        .post(&url)
        .header("authorization", &format!("Bearer {key}"))
        .send_json(&body)
        .map_err(|err| format!("Decisions could not be reached: {err}"))?;
    let status = reply.status();
    let bytes = reply
        .body_mut()
        .with_config()
        .limit(MOST_REPLY as u64)
        .read_to_vec()
        .map_err(|_| "Decisions answered more than any answer needs".to_owned())?;
    let read: Value = serde_json::from_slice(&bytes).unwrap_or_default();
    if !status.is_success() {
        let why = read["error"]["message"]
            .as_str()
            .unwrap_or("no reason given");
        return Err(format!("Decisions refused it ({status}): {why}"));
    }
    let answers = read
        .get("answers")
        .filter(|answers| answers.is_object())
        .cloned()
        .ok_or("Decisions sent no answers")?;
    let cost = read["usage"]["cost"].as_f64().unwrap_or(0.0);
    Ok((answers, cost))
}

/// The start of `now`'s day, in UTC — the day the providers bill by.
pub fn today(now: i64) -> i64 {
    now - now.rem_euclid(86_400)
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
#[path = "deciding_tests.rs"]
mod tests;
