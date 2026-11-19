//! `attack`: the attack stage on a work item. devflow-security tries to
//! exploit the item's change headless, and the report is kept in a run of
//! the item with the exploits beside it; with `run` and `verified`, the
//! session's runs of those exploits are kept on the report.

use std::time::{Duration, SystemTime};

use devflow_engine::attack::{self, Given};
use devflow_engine::config::Config;
use devflow_engine::evidence::Card;
use devflow_engine::review::{Git, Personas};
use serde_json::{json, Value};

use super::{context_of, item_here, item_of, redact, signed};
use crate::project::{self, Project};
use crate::server::Server;

/// How long the attacker may take.
pub const BUDGET: Duration = Duration::from_secs(40 * 60);

pub fn attack(server: &Server, params: Value) -> Result<Value, String> {
    let project = server.project();
    let state = project.read();
    let config = super::config_for(&project, &state, &server.consent, "attack")?;
    on_item(server, &project, config, &params, &super::review::reach)
}

/// The `verified` the session sends: what each exploit run showed.
fn verified_of(params: &Value) -> Result<Vec<Value>, String> {
    match params.get("verified") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(list)) if list.len() <= attack::MOST_HYPOTHESES => Ok(list.clone()),
        Some(Value::Array(_)) => Err(format!(
            "`verified` lists at most {} runs",
            attack::MOST_HYPOTHESES
        )),
        Some(_) => {
            Err("`verified` is a list of { hypothesis, result, evidence, test? }".to_owned())
        }
    }
}

/// The attack on an item, or the session's runs kept on one of its reports.
pub fn on_item(
    server: &Server,
    project: &Project,
    config: &Config,
    params: &Value,
    reach: devflow_engine::review::Reach,
) -> Result<Value, String> {
    let id = item_of(params).ok_or("the attack is asked with its `item`")?;
    let item = item_here(project, &id)?;
    let runs = project.runs();
    let verified = verified_of(params)?;
    if let Some(run) = super::text(params, "run") {
        if verified.is_empty() {
            return Err("with `run`, send `verified`: what each exploit run showed".to_owned());
        }
        let targets = super::targets_in_force(project, config, &server.consent);
        devflow_engine::security::refused(&verified, &targets)?;
        let at = runs
            .found(&item.id, Some(&run), attack::REPORT)
            .ok_or_else(|| format!("run {run} of {} has no {}", item.id, attack::REPORT))?;
        let folder = at.parent().ok_or("a run has a folder")?.to_path_buf();
        let mut in_force = config.clone();
        in_force.security.targets = targets;
        let report = attack::verified(&folder, &in_force, &verified)?;
        let done = attack::Done {
            folder: folder.display().to_string(),
            stamp: run,
            report,
        };
        signed(project, &item.id, &attack::comment(&done));
        return Ok(attack::summary(&done));
    }
    if !verified.is_empty() {
        return Err("`verified` goes with the attack's `run`".to_owned());
    }
    let root = project.root.as_path();
    let started = devflow_engine::started::start_of(&runs, &item.id);
    let base = super::text(params, "base");
    let base = devflow_engine::git::review_base(root, base.as_deref().or(started.as_deref()))
        .map_err(|err| err.to_string())?;
    let said = |err: devflow_engine::git::GitError| err.to_string();
    let head = devflow_engine::git::head_of(root).map_err(said)?;
    let read = devflow_engine::git::review_diff(root, &base, &head).map_err(said)?;
    if read.files.is_empty() || read.diff.trim().is_empty() {
        return Err(format!(
            "nothing to attack: the diff from BASE {base} is empty"
        ));
    }
    let targets = super::targets_in_force(project, config, &server.consent);
    let env = context_of(project, &item, &targets).environment();
    let evidence = super::gate::newest(&runs, &item.id, "evidence.json");
    let review = super::gate::newest(&runs, &item.id, "findings.json");
    let teams = project.teams();
    let personal = project::personal_reviewers();
    let redacting = |text: &str| redact(text);
    let done = attack::attacked(&Given {
        root,
        runs: &runs,
        config,
        card: Card {
            id: &item.id,
            title: &item.title,
            body: &item.body,
        },
        git: Git {
            base: &base,
            head: &head,
            files: &read.files,
            diff: &read.diff,
        },
        brief: None,
        evidence: evidence.as_ref().map(|(_, evidence)| evidence),
        review: review.as_ref().map(|(_, findings)| findings),
        env: &env,
        at: SystemTime::now(),
        budget: BUDGET,
        reach,
        redact: &redacting,
        personas: Personas {
            dialect: &devflow_engine::Dialect::DEVFLOW,
            personal: personal.as_deref(),
            teams: &teams,
        },
        retro: false,
    })?;
    signed(project, &item.id, &attack::comment(&done));
    Ok(attack::summary(&done))
}

/// The attack asked with a review by name (`attack: true`), on the item it
/// reviewed: its answer, or why it did not run, beside the review's.
pub fn after_review(
    server: &Server,
    project: &Project,
    config: &Config,
    item: &str,
    reach: devflow_engine::review::Reach,
) -> Value {
    match on_item(server, project, config, &json!({ "item": item }), reach) {
        Ok(answer) => answer,
        Err(why) => json!({ "error": why }),
    }
}
