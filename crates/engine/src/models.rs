//! Which model each stage runs on: a stage's own `model`, else the tier the
//! models preset gives it, which [`crate::review::model_for`] turns into a
//! model of the agent's CLI.

use crate::config::{Agent, Config, Models, Reviewer};
use crate::scale;

/// The reading before the review's, on a large model.
pub const ANALYSIS: &str = "analysis";

/// The preset in force: `economy` when devflow.yaml says none.
pub fn preset(config: &Config) -> Models {
    config.models.unwrap_or(Models::Economy)
}

/// The tier `models` gives `stage`; `None` leaves the CLI's default.
pub fn tier(models: Models, stage: &str) -> Option<&'static str> {
    match (models, stage) {
        (Models::Quality, _) => Some("large"),
        (Models::Economy, "execution" | "review") => Some("small"),
        (Models::Economy, ANALYSIS) => Some("large"),
        (Models::Economy, _) => None,
    }
}

/// What `stage` runs on as devflow.yaml says it, a tier or an id: its own
/// `model`, else the preset's tier.
pub fn stage_model(config: &Config, stage: &str) -> Option<String> {
    let own = if stage == ANALYSIS {
        config
            .review
            .analysis
            .as_ref()
            .and_then(|analysis| analysis.model.as_deref())
    } else {
        config.stages.model(stage)
    };
    own.or_else(|| tier(preset(config), stage))
        .map(str::to_owned)
}

/// The model a card's session opens on with `agent`: the execution's.
/// `None` leaves the CLI's own default. Set once, at the start: a model
/// changed mid-session throws away the prompt cache.
pub fn session_model(config: &Config, agent: Agent) -> Option<String> {
    crate::review::model_for(agent, stage_model(config, "execution").as_deref())
}

/// Whether the analysis runs: as `review.analysis` says, else only once a
/// models preset is written.
pub fn analysis_on(config: &Config) -> bool {
    match &config.review.analysis {
        Some(analysis) => analysis.enabled,
        None => config.models.is_some(),
    }
}

/// The model of a reviewer that names none: the review stage's `model`, or
/// the preset's once a preset or the analysis is written. Otherwise none, so
/// a devflow.yaml from before the presets reviews as it did.
pub fn review_default(config: &Config) -> Option<String> {
    if let Some(model) = &config.stages.review.model {
        return Some(model.clone());
    }
    (config.models.is_some() || analysis_on(config))
        .then(|| tier(preset(config), "review").map(str::to_owned))
        .flatten()
}

/// The models each stage runs on as devflow.yaml says them, and what the
/// card's session and the analysis open with on `agent`.
pub fn plan(config: &Config, agent: Agent) -> serde_json::Value {
    let stages: serde_json::Map<String, serde_json::Value> = crate::config::STAGES
        .iter()
        .chain(std::iter::once(&ANALYSIS))
        .filter_map(|stage| Some(((*stage).to_owned(), stage_model(config, stage)?.into())))
        .collect();
    serde_json::json!({
        "preset": preset(config).word(),
        "said": config.models.is_some(),
        "stages": stages,
        "session": session_model(config, agent),
        "review_default": review_default(config),
        "analysis": analysis_on(config),
    })
}

/// One headless reading of a diff, and the stage it is for.
#[derive(Debug, Clone, PartialEq)]
pub struct Reader {
    pub reviewer: Reviewer,
    pub stage: &'static str,
}

/// Who reads a diff: the review's reviewers (one when `one`), each on its
/// model, then the analysis's reader when it is on and the diff is past
/// small or touches a sensitive path. The analysis reads every axis, on the
/// first reviewer's agent (Claude Code with none).
pub fn readers(config: &Config, one: bool, files: &[String], diff: &str) -> Vec<Reader> {
    let default = review_default(config);
    let mut readers: Vec<Reader> = scale::reviewers(&config.review, one)
        .into_iter()
        .map(|mut reviewer| {
            if reviewer.model.is_none() {
                reviewer.model.clone_from(&default);
            }
            Reader {
                reviewer,
                stage: "review",
            }
        })
        .collect();
    if analysis_on(config) && !small(config, files, diff) {
        let agent = config
            .review
            .reviewers
            .first()
            .map_or(Agent::Claude, |first| first.agent);
        readers.push(Reader {
            reviewer: Reviewer {
                agent,
                persona: scale::ALL_AXES.to_owned(),
                model: stage_model(config, ANALYSIS),
            },
            stage: ANALYSIS,
        });
    }
    readers
}

/// A diff `review.scale` (its defaults when off) calls small.
fn small(config: &Config, files: &[String], diff: &str) -> bool {
    let scale = config.review.scale.clone().unwrap_or_default();
    scale::sized(&scale, files, diff).one
}

#[cfg(test)]
#[path = "models_tests.rs"]
mod tests;
