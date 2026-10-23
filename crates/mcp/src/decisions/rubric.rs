//! A rubric: questions for Decisions and the thresholds that turn its answers
//! into pass, grey or fail — the format assay writes.
//!
//! Pure on purpose: what a threshold means is a rule worth testing on its own,
//! apart from anything that reaches the network.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Rubric {
    /// The file's name is the rubric's, whatever the file says.
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    /// As Decisions reads them, by question id.
    pub questions: Value,
    #[serde(default)]
    pub thresholds: BTreeMap<String, Threshold>,
}

/// `min`: pass at or above. `max`: pass at or below, for a score where lower
/// is better. `grey`: the far edge of the band left to a person. `adjacent`:
/// a choice on an ordered scale is as sure as its option and the likelier of
/// its neighbours together.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq)]
pub struct Threshold {
    #[serde(default)]
    pub min: Option<f64>,
    #[serde(default)]
    pub max: Option<f64>,
    #[serde(default)]
    pub grey: Option<f64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub adjacent: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Grey,
    Fail,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Grey => "grey",
            Self::Fail => "fail",
        }
    }
}

/// The number an answer is judged by, whatever its type.
pub fn scalar(answer: &Value) -> Option<f64> {
    if let Some(p) = answer.get("noul").or_else(|| answer.get("probability")) {
        return p.as_f64();
    }
    if let Some(score) = answer.get("score").and_then(Value::as_f64) {
        return Some(score);
    }
    if let Some(confidence) = answer.get("confidence").and_then(Value::as_f64) {
        return Some(confidence);
    }
    let choice = answer.get("choice")?;
    let key = choice
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| choice.to_string());
    ["probabilities", "distribution"]
        .iter()
        .find_map(|field| answer.get(field)?.get(&key)?.as_f64())
}

/// A choice with the likelier of the options beside it in `options`: medium
/// at 0.49 next to high at 0.32 is sure the answer is one of those two.
pub fn banded(answer: &Value, options: &[&str]) -> Option<f64> {
    let chosen = scalar(answer)?;
    let choice = answer.get("choice")?.as_str()?;
    let at = options.iter().position(|option| *option == choice)?;
    let of = |option: &str| {
        ["probabilities", "distribution"]
            .iter()
            .find_map(|field| answer.get(field)?.get(option)?.as_f64())
            .unwrap_or(0.0)
    };
    let before = at.checked_sub(1).map_or(0.0, |before| of(options[before]));
    let after = options.get(at + 1).map_or(0.0, |after| of(after));
    Some(chosen + before.max(after))
}

/// The number `id`'s answer is judged by: banded where its threshold says so.
fn value_of(rubric: &Rubric, id: &str, answer: Option<&Value>) -> Option<f64> {
    let answer = answer?;
    if !rubric.thresholds.get(id).is_some_and(|one| one.adjacent) {
        return scalar(answer);
    }
    let options: Vec<&str> = rubric.questions[id]["options"]
        .as_array()
        .map(|options| options.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    banded(answer, &options).or_else(|| scalar(answer))
}

/// One answer's number against its threshold. Nothing to compare, or nothing
/// to compare against, is grey: a guess must not pass or fail on a default.
pub fn verdict_of(value: Option<f64>, threshold: Option<&Threshold>) -> Verdict {
    let (Some(value), Some(threshold)) = (value, threshold) else {
        return Verdict::Grey;
    };
    if let Some(min) = threshold.min {
        if value >= min {
            return Verdict::Pass;
        }
        return match threshold.grey {
            Some(grey) if value >= grey => Verdict::Grey,
            _ => Verdict::Fail,
        };
    }
    if let Some(max) = threshold.max {
        if value <= max {
            return Verdict::Pass;
        }
        return match threshold.grey {
            Some(grey) if value <= grey => Verdict::Grey,
            _ => Verdict::Fail,
        };
    }
    Verdict::Grey
}

/// Every question of `rubric` judged against `answers`, and the outcome: the
/// worst of them, fail over grey over pass.
pub fn judged(rubric: &Rubric, answers: &Value) -> (Verdict, Value) {
    let ids: Vec<&String> = rubric
        .questions
        .as_object()
        .map(|questions| questions.keys().collect())
        .unwrap_or_default();
    let mut verdicts = serde_json::Map::new();
    let mut worst = Verdict::Pass;
    for id in ids {
        let answer = answers.get(id);
        let value = value_of(rubric, id, answer);
        let one = verdict_of(value, rubric.thresholds.get(id));
        worst = match (worst, one) {
            (Verdict::Fail, _) | (_, Verdict::Fail) => Verdict::Fail,
            (Verdict::Grey, _) | (_, Verdict::Grey) => Verdict::Grey,
            _ => Verdict::Pass,
        };
        verdicts.insert(
            id.clone(),
            json!({ "verdict": one.as_str(), "value": value }),
        );
    }
    (worst, Value::Object(verdicts))
}

#[cfg(test)]
#[path = "rubric_tests.rs"]
mod tests;
