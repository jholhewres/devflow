//! Which model each stage runs on: a stage's own `model`, else the tier the
//! models preset gives it, which [`crate::review::model_for`] turns into a
//! model of the agent's CLI.

use crate::config::{Agent, AttackRun, Config, Models, Reviewer};
use crate::scale;

/// The reading before the review's, on a large model.
pub const ANALYSIS: &str = "analysis";
/// The attack's reading, on a large model unless `review.attack.model` says.
pub const ATTACK: &str = "attack";
/// The persona the attack reads as.
pub const ATTACK_PERSONA: &str = "devflow-security";

/// The preset in force: `economy` when devflow.yaml says none. `models:
/// economy` is the one to write (docs/measurements/2026-11-presets.md).
pub fn preset(config: &Config) -> Models {
    config.models.unwrap_or(Models::Economy)
}

/// The tier `models` gives `stage`; `None` leaves the CLI's default.
pub fn tier(models: Models, stage: &str) -> Option<&'static str> {
    match (models, stage) {
        (Models::Quality, _) => Some("large"),
        (Models::Economy, "execution" | "review") => Some("small"),
        (Models::Economy, ANALYSIS | ATTACK) => Some("large"),
        (Models::Economy, _) => None,
    }
}

/// Where a model a stage or a reviewer runs on came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum From {
    /// The stage's own `model`.
    Stage,
    /// The reviewer's own `model`.
    Reviewer,
    /// The tier the models preset gives it.
    Preset,
    /// Nothing said: the CLI's own default.
    Default,
}

/// A model as devflow.yaml comes to it, a tier or an id, and where it came
/// from; `None` leaves the CLI's default.
pub type Resolved = (Option<String>, From);

/// What `stage` runs on as devflow.yaml says it: its own `model`, else the
/// preset's tier, else the CLI's default.
pub fn resolved(config: &Config, stage: &str) -> Resolved {
    let own = match stage {
        ANALYSIS => config
            .review
            .analysis
            .as_ref()
            .and_then(|analysis| analysis.model.as_deref()),
        _ => config.stages.model(stage),
    };
    match (own, tier(preset(config), stage)) {
        (Some(own), _) => (Some(own.to_owned()), From::Stage),
        (None, Some(tier)) => (Some(tier.to_owned()), From::Preset),
        (None, None) => (None, From::Default),
    }
}

/// What `stage` runs on as devflow.yaml says it, a tier or an id: its own
/// `model`, else the preset's tier.
pub fn stage_model(config: &Config, stage: &str) -> Option<String> {
    resolved(config, stage).0
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

/// When the attack runs as devflow.yaml says: `off` when it names no
/// attack stage, `sensitive` when it names one with no `run`.
pub fn attack_run(config: &Config) -> AttackRun {
    config.stages.attack.run
}

/// Whether a diff could make the attack stage due: `per-item` and
/// `sensitive` read it; `off` and `release` never are, so their diff is
/// not worth reading.
pub fn attack_reads_the_diff(config: &Config) -> bool {
    matches!(
        attack_run(config),
        AttackRun::PerItem | AttackRun::Sensitive
    )
}

/// Whether the attack stage is due on this diff: `per-item` always,
/// `sensitive` when `review.scale` (its defaults when off) does not call it
/// small; `off` and `release` never, a release's being asked by name
/// ([`attack_asked`]).
pub fn attack_on(config: &Config, files: &[String], diff: &str) -> bool {
    match attack_run(config) {
        AttackRun::PerItem => true,
        AttackRun::Sensitive => !small(config, files, diff),
        AttackRun::Off | AttackRun::Release => false,
    }
}

/// Whether a review sends its item on to the attack: it is due on this diff
/// and, unless it runs per-item, has not run on the item yet. With
/// `sensitive` one attack is enough: a fix is proven by its exploit test
/// turning green, not by attacking again.
pub fn attack_next(config: &Config, files: &[String], diff: &str, attacked: bool) -> bool {
    attack_on(config, files, diff) && (!attacked || attack_run(config) == AttackRun::PerItem)
}

/// The configuration a review asked for the attack by name runs with: a
/// release's attack, or one more on any diff. Refused while it is off.
pub fn attack_asked(config: &Config) -> Result<Config, String> {
    if config.stages.attack.run == AttackRun::Off {
        return Err(
            "stages.attack is off: the person sets its run to release, sensitive or per-item first"
                .to_owned(),
        );
    }
    let mut asked = config.clone();
    asked.stages.attack.run = AttackRun::PerItem;
    Ok(asked)
}

/// The model of a reviewer that names none: the review stage's `model`, or
/// the preset's once a preset or the analysis is written. Otherwise none, so
/// a devflow.yaml from before the presets reviews as it did.
pub fn review_default(config: &Config) -> Option<String> {
    review_resolved(config).0
}

/// [`review_default`], with where it came from.
fn review_resolved(config: &Config) -> Resolved {
    if let Some(model) = &config.stages.review.model {
        return (Some(model.clone()), From::Stage);
    }
    match (config.models.is_some() || analysis_on(config))
        .then(|| tier(preset(config), "review"))
        .flatten()
    {
        Some(tier) => (Some(tier.to_owned()), From::Preset),
        None => (None, From::Default),
    }
}

/// What a reviewer runs on: its own `model`, else [`review_default`].
fn reviewer_resolved(config: &Config, reviewer: &Reviewer) -> Resolved {
    match &reviewer.model {
        Some(model) => (Some(model.clone()), From::Reviewer),
        None => review_resolved(config),
    }
}

/// The agent the extra readings run on: the first reviewer's, Claude Code
/// with none.
pub fn first_agent(config: &Config) -> Agent {
    config
        .review
        .reviewers
        .first()
        .map_or(Agent::Claude, |first| first.agent)
}

/// The models each stage runs on as devflow.yaml says them, and what the
/// card's session and the analysis open with on `agent`.
pub fn plan(config: &Config, agent: Agent) -> serde_json::Value {
    let origins = origins(config, agent);
    // The stages map is the rows' own, so what it says is what status lists.
    let stages: serde_json::Map<String, serde_json::Value> = origins
        .iter()
        .filter(|row| row.who.is_none())
        .filter_map(|row| Some((row.stage.clone(), row.said.clone()?.into())))
        .collect();
    let mut plan = serde_json::json!({
        "preset": preset(config).word(),
        "said": config.models.is_some(),
        "agent": agent.word(),
        "stages": stages,
        "session": session_model(config, agent),
        "review_default": review_default(config),
        "analysis": analysis_on(config),
        "origins": origins,
    });
    if attack_run(config) != AttackRun::Off {
        plan["attack"] = attack_run(config).word().into();
    }
    plan
}

/// What one stage, or one reviewer, runs on and why.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Origin {
    pub stage: String,
    /// The reviewer, `<agent> <persona>`, on a reviewer's row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub who: Option<String>,
    /// The tier or id devflow.yaml comes to; `None` leaves the CLI's default.
    pub said: Option<String>,
    /// What that is on the row's CLI ([`crate::review::model_for`]).
    pub runs_on: Option<String>,
    pub from: From,
}

/// What each built-in stage, each reviewer, the analysis and the attack run
/// on as devflow.yaml says it, and where that came from. `agent` is the
/// session's CLI; a reviewer's row is on its own, and the analysis's and
/// the attack's on the first reviewer's.
pub fn origins(config: &Config, agent: Agent) -> Vec<Origin> {
    let row = |stage: &str, who: Option<String>, on: Agent, (said, from): Resolved| Origin {
        stage: stage.to_owned(),
        who,
        runs_on: crate::review::model_for(on, said.as_deref()),
        said,
        from,
    };
    let mut rows: Vec<Origin> = crate::config::STAGES
        .iter()
        .map(|stage| {
            let said = match *stage {
                "review" => review_resolved(config),
                _ => resolved(config, stage),
            };
            // The attack runs where the analysis does, on the first reviewer's CLI.
            let on = if *stage == ATTACK {
                first_agent(config)
            } else {
                agent
            };
            row(stage, None, on, said)
        })
        .collect();
    for reviewer in &config.review.reviewers {
        let who = format!("{} {}", reviewer.agent.word(), reviewer.persona);
        rows.push(row(
            "review",
            Some(who),
            reviewer.agent,
            reviewer_resolved(config, reviewer),
        ));
    }
    if analysis_on(config) {
        rows.push(row(
            ANALYSIS,
            None,
            first_agent(config),
            resolved(config, ANALYSIS),
        ));
    }
    rows
}

/// One headless reading of a diff, and the stage it is for.
#[derive(Debug, Clone, PartialEq)]
pub struct Reader {
    pub reviewer: Reviewer,
    pub stage: &'static str,
}

/// Who reads a diff: the review's reviewers (one when `one`), each on its
/// model, then the analysis's reader when it is on and the diff is past
/// small or touches a sensitive path, on the first reviewer's agent (Claude
/// Code with none). The attack is a stage of its own, not a reader here.
pub fn readers(config: &Config, one: bool, files: &[String], diff: &str) -> Vec<Reader> {
    let mut readers: Vec<Reader> = scale::reviewers(&config.review, one)
        .into_iter()
        .map(|mut reviewer| {
            reviewer.model = reviewer_resolved(config, &reviewer).0;
            Reader {
                reviewer,
                stage: "review",
            }
        })
        .collect();
    let agent = first_agent(config);
    let extra = |persona: &str, stage: &'static str| Reader {
        reviewer: Reviewer {
            agent,
            persona: persona.to_owned(),
            model: stage_model(config, stage),
        },
        stage,
    };
    if analysis_on(config) && !small(config, files, diff) {
        readers.push(extra(scale::ALL_AXES, ANALYSIS));
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
