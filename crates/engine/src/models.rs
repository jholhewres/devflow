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

/// The preset in force: `economy` when devflow.yaml says none.
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

/// What `stage` runs on as devflow.yaml says it, a tier or an id: its own
/// `model`, else the preset's tier.
pub fn stage_model(config: &Config, stage: &str) -> Option<String> {
    let own = match stage {
        ANALYSIS => config
            .review
            .analysis
            .as_ref()
            .and_then(|analysis| analysis.model.as_deref()),
        ATTACK => config
            .review
            .attack
            .as_ref()
            .and_then(|attack| attack.model.as_deref()),
        _ => config.stages.model(stage),
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

/// When the attack runs as devflow.yaml says: `off` unless it says.
pub fn attack_run(config: &Config) -> AttackRun {
    config
        .review
        .attack
        .as_ref()
        .map_or(AttackRun::Off, |attack| attack.run)
}

/// Whether a review of this diff gets the attack's reading: `per-item`
/// always, `sensitive` when `review.scale` (its defaults when off) does not
/// call it small; `off` and `release` never, a release's being asked by
/// name ([`attack_asked`]).
pub fn attack_on(config: &Config, files: &[String], diff: &str) -> bool {
    match attack_run(config) {
        AttackRun::PerItem => true,
        AttackRun::Sensitive => !small(config, files, diff),
        AttackRun::Off | AttackRun::Release => false,
    }
}

/// The configuration a review asked for the attack by name runs with: a
/// release's attack, or one more on any diff. Refused while it is off.
pub fn attack_asked(config: &Config) -> Result<Config, String> {
    let Some(attack) = config
        .review
        .attack
        .as_ref()
        .filter(|attack| attack.run != AttackRun::Off)
    else {
        return Err(
            "review.attack is off: the person sets it to release, sensitive or per-item first"
                .to_owned(),
        );
    };
    let mut asked = config.clone();
    asked.review.attack = Some(crate::config::Attack {
        run: AttackRun::PerItem,
        model: attack.model.clone(),
    });
    Ok(asked)
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
        .chain([&ANALYSIS, &ATTACK])
        .filter_map(|stage| {
            let model = match *stage {
                "review" => review_default(config),
                ANALYSIS if !analysis_on(config) => None,
                ATTACK if attack_run(config) == AttackRun::Off => None,
                _ => stage_model(config, stage),
            };
            Some(((*stage).to_owned(), model?.into()))
        })
        .collect();
    let mut plan = serde_json::json!({
        "preset": preset(config).word(),
        "said": config.models.is_some(),
        "stages": stages,
        "session": session_model(config, agent),
        "review_default": review_default(config),
        "analysis": analysis_on(config),
        "origins": origins(config, agent),
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
    /// `stage` (its own `model`), `reviewer` (the reviewer's), `preset`
    /// (the models preset's tier) or `default` (the CLI's own).
    pub from: &'static str,
}

/// What each built-in stage, each reviewer, the analysis and the attack run
/// on as devflow.yaml says it, and where that came from. `agent` is the
/// session's CLI; a reviewer's row is on its own, and the analysis's and
/// the attack's on the first reviewer's.
pub fn origins(config: &Config, agent: Agent) -> Vec<Origin> {
    let row =
        |stage: &str, who: Option<String>, on: Agent, said: (Option<String>, &'static str)| {
            Origin {
                stage: stage.to_owned(),
                who,
                runs_on: crate::review::model_for(on, said.0.as_deref()),
                said: said.0,
                from: said.1,
            }
        };
    let preset_tier = |stage: &str| -> (Option<String>, &'static str) {
        match tier(preset(config), stage) {
            Some(tier) => (Some(tier.to_owned()), "preset"),
            None => (None, "default"),
        }
    };
    let review = match &config.stages.review.model {
        Some(model) => (Some(model.clone()), "stage"),
        None => match review_default(config) {
            Some(tier) => (Some(tier), "preset"),
            None => (None, "default"),
        },
    };
    let first = config
        .review
        .reviewers
        .first()
        .map_or(Agent::Claude, |first| first.agent);
    let mut rows: Vec<Origin> = crate::config::STAGES
        .iter()
        .map(|stage| {
            let said = match (*stage, config.stages.model(stage)) {
                ("review", _) => review.clone(),
                (_, Some(model)) => (Some(model.to_owned()), "stage"),
                (_, None) => preset_tier(stage),
            };
            row(stage, None, agent, said)
        })
        .collect();
    for reviewer in &config.review.reviewers {
        let said = match &reviewer.model {
            Some(model) => (Some(model.clone()), "reviewer"),
            None => review.clone(),
        };
        let who = format!("{} {}", reviewer.agent.word(), reviewer.persona);
        rows.push(row("review", Some(who), reviewer.agent, said));
    }
    let own = |model: Option<&String>, stage: &str| match model {
        Some(model) => (Some(model.clone()), "stage"),
        None => preset_tier(stage),
    };
    if analysis_on(config) {
        let model = config
            .review
            .analysis
            .as_ref()
            .and_then(|one| one.model.as_ref());
        rows.push(row(ANALYSIS, None, first, own(model, ANALYSIS)));
    }
    if attack_run(config) != AttackRun::Off {
        let model = config
            .review
            .attack
            .as_ref()
            .and_then(|one| one.model.as_ref());
        rows.push(row(ATTACK, None, first, own(model, ATTACK)));
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
/// small or touches a sensitive path, then the attack's when
/// [`attack_on`]. The analysis reads every axis and the attack security,
/// each on the first reviewer's agent (Claude Code with none).
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
    // The extra readings run on the first reviewer's agent, Claude Code with none.
    let agent = config
        .review
        .reviewers
        .first()
        .map_or(Agent::Claude, |first| first.agent);
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
    if attack_on(config, files, diff) {
        readers.push(extra(ATTACK_PERSONA, ATTACK));
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
