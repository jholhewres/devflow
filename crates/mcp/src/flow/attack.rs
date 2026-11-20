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

/// The answer with the report written beside it as md, JSON and SARIF and
/// its issue drafts, each named by its path.
fn with_files(folder: &std::path::Path, report: &Value, mut answer: Value) -> Value {
    match devflow_engine::attack_report::written(folder, report) {
        Ok(files) => {
            answer["files"] = json!(files
                .iter()
                .map(|file| folder.join(file).display().to_string())
                .collect::<Vec<_>>());
        }
        Err(why) => answer["files_error"] = json!(why),
    }
    answer
}

pub fn attack(server: &Server, params: Value) -> Result<Value, String> {
    let project = server.project();
    let state = project.read();
    let config = super::config_for(&project, &state, &server.consent, "attack")?;
    if item_of(&params).is_none() && super::text(&params, "head").is_some() {
        return on_range(&project, config, &params, &super::review::reach);
    }
    on_item(server, &project, config, &params, &super::review::reach)
}

/// The attack on a range with no item: its run and each exploit kept in the
/// project's vault, outside the checkout, under the range's name.
pub fn on_range(
    project: &Project,
    config: &Config,
    params: &Value,
    reach: devflow_engine::review::Reach,
) -> Result<Value, String> {
    use devflow_engine::adhoc::{self, Subject};
    use devflow_engine::git;
    let said = |err: git::GitError| err.to_string();
    let revision = |key: &str| -> Result<String, String> {
        match super::text(params, key) {
            Some(word) if git::plain_revision(&word) => Ok(word),
            Some(_) => Err(format!("`{key}` is a branch or a commit")),
            None => Err("a range is attacked with `base` and `head`".to_owned()),
        }
    };
    let (base, head) = (revision("base")?, revision("head")?);
    if super::text(params, "run").is_some() || params.get("verified").is_some() {
        return Err("a range's attack runs once: its exploits wait in the vault for `devflow attack promote`".to_owned());
    }
    let root = project.root.as_path();
    let head = git::commit_of(root, &head).map_err(said)?;
    let base = git::merge_base(root, &base, &head).map_err(said)?;
    let label = adhoc::label(
        &Subject::Range {
            base: base.clone(),
            head: head.clone(),
        },
        &base,
        &head,
    );
    let home = devflow_engine::vault::home(&project.cache(), root)?;
    let runs = devflow_engine::vault::runs(home, root);
    let at = SystemTime::now();
    // One month's budget for the project's attacks, with or without an item.
    let budget = config.stages.attack.budget;
    attack::month_left(&project.runs().home, budget, at)?;
    let tree = project.review_trees().join(format!(
        "attack-{label}-{}",
        devflow_engine::runs::stamp(at)
    ));
    git::add_detached(root, &tree, &head).map_err(said)?;
    let detached = super::review::Detached {
        root,
        at: tree.clone(),
    };
    let read = git::review_diff(&tree, &base, &head).map_err(said)?;
    if read.files.is_empty() || read.diff.trim().is_empty() {
        return Err(format!("nothing to attack: {base}..{head} changes nothing"));
    }
    let teams = project.teams();
    let personal = project::personal_reviewers();
    let redacting = |text: &str| redact(text);
    let title = format!(
        "{}..{}",
        &base[..12.min(base.len())],
        &head[..12.min(head.len())]
    );
    let done = attack::attacked(&Given {
        root: &tree,
        runs: &runs,
        config,
        card: Card {
            id: &label,
            title: &title,
            body: "",
        },
        git: Git {
            base: &base,
            head: &head,
            files: &read.files,
            diff: &read.diff,
        },
        brief: None,
        evidence: None,
        review: None,
        env: &super::review::standalone_env(),
        at,
        budget: BUDGET,
        reach,
        redact: &redacting,
        personas: Personas {
            dialect: &devflow_engine::Dialect::DEVFLOW,
            personal: personal.as_deref(),
            teams: &teams,
        },
        retro: super::text(params, "mode").as_deref() == Some("retro"),
        scratch: Some(&project.cache().join("trees")),
        flow: None,
    });
    drop(detached);
    let done = done?;
    // Counted in the project's ledger too, where the month is read.
    let _ = devflow_engine::attack_metrics::record(
        &project.runs().home,
        &label,
        &done.stamp,
        &done.report,
    );
    let folder = std::path::PathBuf::from(&done.folder);
    let mut answer = with_files(&folder, &done.report, attack::summary(&done));
    answer["attacked"] = json!(label);
    answer["vault"] = json!(done.folder);
    answer["next"] = json!(format!(
        "The exploits stay in the vault, outside the repository. `devflow attack promote {label} <hypothesis> --run {}` copies one into the repository at its path, once its fix lands.",
        done.stamp
    ));
    Ok(answer)
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
    let proving = match params.get("prove") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Bool(true)) => true,
        Some(_) => return Err("`prove` is true or false".to_owned()),
    };
    if proving {
        let run = super::text(params, "run").ok_or("`prove` goes with the attack's `run`")?;
        if !verified.is_empty() {
            return Err("`prove` and `verified` are two calls".to_owned());
        }
        let at = runs
            .found(&item.id, Some(&run), attack::REPORT)
            .ok_or_else(|| format!("run {run} of {} has no {}", item.id, attack::REPORT))?;
        let folder = at.parent().ok_or("a run has a folder")?.to_path_buf();
        let root = project.root.as_path();
        let head = devflow_engine::git::head_of(root).map_err(|err| err.to_string())?;
        let report = attack::prove(&attack::Proving {
            root,
            folder: &folder,
            config,
            head: &head,
            scratch: &project.cache().join("trees"),
            at: SystemTime::now(),
        })?;
        let done = attack::Done {
            folder: folder.display().to_string(),
            stamp: run,
            report,
        };
        signed(project, &item.id, &attack::comment(&done));
        let mut answer = with_files(&folder, &done.report, attack::summary(&done));
        answer["proofs"] = json!(done.report["hypotheses"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|one| !one["proof"].is_null())
            .map(|one| json!({ "id": one["id"], "status": one["status"], "proof": one["proof"] }))
            .collect::<Vec<_>>());
        return Ok(answer);
    }
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
        return Ok(with_files(&folder, &done.report, attack::summary(&done)));
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
    // A flow across repositories, from the project's workspace manifest.
    let flowed = match super::text(params, "flow") {
        Some(name) => {
            let workspace = devflow_engine::workspace::read(root)?.ok_or_else(|| {
                format!(
                    "`flow` names a flow of {}, which this project does not have",
                    devflow_engine::workspace::MANIFEST
                )
            })?;
            Some(devflow_engine::workspace::flowed(&workspace, &name)?)
        }
        None => None,
    };
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
        scratch: Some(&project.cache().join("trees")),
        flow: flowed.as_ref(),
    })?;
    signed(project, &item.id, &attack::comment(&done));
    let folder = std::path::PathBuf::from(&done.folder);
    Ok(with_files(&folder, &done.report, attack::summary(&done)))
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
