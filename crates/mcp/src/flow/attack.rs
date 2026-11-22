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
    // What only the person gives is asked of them, never read from `params`.
    let launching = super::text(&params, "run").is_none();
    let asked = crate::ready::before_attack(server, &project, launching)?;
    let state = project.read();
    let config = super::config_for(&project, &state, &server.consent, "attack")?;
    let (config, budget_note) = budgeted(server, &project, config);
    let config = &config;
    let mut answer = if item_of(&params).is_none() && super::text(&params, "head").is_some() {
        on_range(server, &project, config, &params, &super::review::reach)
    } else {
        on_item(server, &project, config, &params, &super::review::reach)
    }?;
    if let Some(asked) = asked {
        answer["asked"] = asked;
    }
    if let Some(note) = budget_note {
        answer["budget_note"] = note;
    }
    Ok(answer)
}

/// The attack on a range with no item: its run and each exploit kept in the
/// project's vault, outside the checkout, under the range's name.
pub fn on_range(
    server: &Server,
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
    let ledger = project.runs().home;
    if let Some(run) = super::text(params, "run") {
        return range_run(
            server,
            project,
            config,
            params,
            (&runs, &label, &run),
            &ledger,
        );
    }
    if params.get("verified").is_some() || params.get("prove").is_some() {
        return Err("`verified` and `prove` go with the range's attack `run`".to_owned());
    }
    let at = SystemTime::now();
    // One month's budget for the project's attacks, with or without an item.
    let budget = config.stages.attack.budget;
    attack::month_left(&ledger, budget, at)?;
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
        stack: None,
        ledger: Some(&ledger),
    });
    drop(detached);
    let done = done?;
    let folder = std::path::PathBuf::from(&done.folder);
    let mut answer = with_files(&folder, &done.report, attack::summary(&done));
    answer["attacked"] = json!(label);
    answer["vault"] = json!(done.folder);
    answer["next"] = json!(format!(
        "The exploits stay in the vault, outside the repository. `devflow attack {label} --promote <hypothesis> --run {}` copies one into the repository at its path, once its fix lands.",
        done.stamp
    ));
    Ok(answer)
}

/// A range's run in the vault, kept again: the session's runs of its
/// exploits (`verified`), or its confirmed exploits proven at their base and
/// at HEAD (`prove`). The attacker is not asked again.
fn range_run(
    server: &Server,
    project: &Project,
    config: &Config,
    params: &Value,
    (runs, label, run): (&devflow_engine::runs::Runs, &str, &str),
    ledger: &std::path::Path,
) -> Result<Value, String> {
    let verified = verified_of(params)?;
    let proving = proving_of(params)?;
    let at = runs
        .found(label, Some(run), attack::REPORT)
        .ok_or_else(|| format!("run {run} of {label} has no {}", attack::REPORT))?;
    let folder = at.parent().ok_or("a run has a folder")?.to_path_buf();
    // A range's run is the vault's: one found in the checkout, committed or
    // put there, is never proven nor counted.
    let checkout = project.root.canonicalize().unwrap_or(project.root.clone());
    if folder
        .canonicalize()
        .unwrap_or(folder.clone())
        .starts_with(&checkout)
    {
        return Err(format!(
            "run {run} of {label} is in the checkout, not in the vault: a range's run is read \
             only from the vault"
        ));
    }
    let report = match (proving, verified.is_empty()) {
        (true, true) => {
            let root = project.root.as_path();
            let head = devflow_engine::git::head_of(root).map_err(|err| err.to_string())?;
            attack::prove_into(
                &attack::Proving {
                    root,
                    folder: &folder,
                    config,
                    head: &head,
                    scratch: &project.cache().join("trees"),
                    at: SystemTime::now(),
                    stack: None,
                },
                Some((ledger, label)),
            )?
        }
        (true, false) => return Err("`prove` and `verified` are two calls".to_owned()),
        (false, true) => {
            return Err(
                "with `run`, send `verified` (what each exploit run showed) or `prove: true`"
                    .to_owned(),
            )
        }
        (false, false) => {
            let targets = super::targets_in_force(project, config, &server.consent);
            devflow_engine::security::refused(&verified, &targets)?;
            let mut in_force = config.clone();
            in_force.security.targets = targets;
            attack::verified_into(&folder, &in_force, &verified, Some((ledger, label)))?
        }
    };
    let done = attack::Done {
        folder: folder.display().to_string(),
        stamp: run.to_owned(),
        report,
    };
    let mut answer = with_files(&folder, &done.report, attack::summary(&done));
    if proving {
        answer["proofs"] = proofs(&done.report);
    }
    answer["attacked"] = json!(label);
    answer["vault"] = json!(done.folder);
    Ok(answer)
}

/// Whether the call proves a run's confirmed exploits.
fn proving_of(params: &Value) -> Result<bool, String> {
    match params.get("prove") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => Ok(false),
        Some(Value::Bool(true)) => Ok(true),
        Some(_) => Err("`prove` is true or false".to_owned()),
    }
}

/// Each proven hypothesis, with its proof.
fn proofs(report: &Value) -> Value {
    json!(report["hypotheses"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|one| !one["proof"].is_null())
        .map(|one| json!({ "id": one["id"], "status": one["status"], "proof": one["proof"] }))
        .collect::<Vec<_>>())
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

/// The stack in force: the one devflow.yaml names, confirmed by the person,
/// and still what compose resolved when they did. Said why when it is not.
fn stack_in_force(
    server: &Server,
    project: &Project,
    config: &Config,
    // The file, docker, and the digest it resolves to now.
) -> Result<Option<(String, std::path::PathBuf, String)>, String> {
    let root = project.root.as_path();
    let Some(named) = config.security.stack.as_deref() else {
        return Ok(None);
    };
    let confirmed = server.consent.confirmed_stack(root);
    use devflow_engine::config::SandboxChoice;
    if matches!(
        config.stages.attack.sandbox,
        Some(SandboxChoice::Bwrap | SandboxChoice::Off)
    ) {
        return Err(
            "security.stack needs the docker sandbox: stages.attack.sandbox is docker or auto"
                .to_owned(),
        );
    }
    let docker = crate::register::on_path("docker").ok_or("security.stack needs docker")?;
    let (_, now) = devflow_engine::stack::resolved(&docker, root, named)?;
    in_force(confirmed, named, &now)?;
    Ok(Some((named.to_owned(), docker, now)))
}

/// Whether the stack `named`, resolving to `now`, is the one the person
/// confirmed: the same file, resolving to what it did then.
pub(crate) fn in_force(
    confirmed: Option<(String, String)>,
    named: &str,
    now: &str,
) -> Result<(), String> {
    let again = "the person confirms it with `devflow config set security.stack` in a terminal";
    match confirmed {
        None => Err(format!("security.stack is not confirmed: {again}")),
        Some((file, _)) if file != named => Err(format!(
            "security.stack names another file than the one confirmed: {again}"
        )),
        Some((_, digest)) if digest != now => {
            Err(format!("the stack changed since it was confirmed: {again}"))
        }
        Some(_) => Ok(()),
    }
}

/// The stack in force, started for this attack and taken down when dropped;
/// one named but not in force is never started, and why is said.
fn started_stack(
    server: &Server,
    project: &Project,
    config: &Config,
) -> Result<(Option<devflow_engine::stack::Up>, Option<String>), String> {
    match stack_in_force(server, project, config) {
        Ok(Some((file, docker, confirmed))) => devflow_engine::stack::up(
            &docker,
            &project.root,
            &file,
            &confirmed,
            &project.cache().join("stacks"),
            &devflow_engine::runs::stamp(SystemTime::now()),
        )
        .map(|up| (Some(up), None)),
        Ok(None) => Ok((None, None)),
        Err(why) => Ok((None, Some(why))),
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
    let proving = proving_of(params)?;
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
        let (stack, _) = started_stack(server, project, config)?;
        let report = attack::prove(&attack::Proving {
            root,
            folder: &folder,
            config,
            head: &head,
            scratch: &project.cache().join("trees"),
            at: SystemTime::now(),
            stack: stack.as_ref(),
        })?;
        let done = attack::Done {
            folder: folder.display().to_string(),
            stamp: run,
            report,
        };
        signed(project, &item.id, &attack::comment(&done));
        let mut answer = with_files(&folder, &done.report, attack::summary(&done));
        answer["proofs"] = proofs(&done.report);
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
    // One named but not in force is said, never started.
    let (stack, not_in_force) = started_stack(server, project, config)?;
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
        stack: stack.as_ref(),
        ledger: None,
    })?;
    drop(stack);
    signed(project, &item.id, &attack::comment(&done));
    let folder = std::path::PathBuf::from(&done.folder);
    let mut answer = with_files(&folder, &done.report, attack::summary(&done));
    if let Some(why) = not_in_force {
        answer["stack"] = json!(why);
    }
    Ok(answer)
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
    let (config, budget_note) = budgeted(server, project, config);
    match on_item(server, project, &config, &json!({ "item": item }), reach) {
        Ok(mut answer) => {
            if let Some(note) = budget_note {
                answer["budget_note"] = note;
            }
            answer
        }
        Err(why) => json!({ "error": why }),
    }
}

/// `config` as an attack runs on it: without a budget the question of 0.6.2
/// and 0.6.3 prefilled, which the person never chose; and a note saying so.
pub fn budgeted(server: &Server, project: &Project, config: &Config) -> (Config, Option<Value>) {
    let budget = config.stages.attack.budget;
    let prefilled = crate::ready::prefilled(&project.root, &server.consent, budget);
    let mut config = config.clone();
    config.stages.attack.budget = crate::ready::in_force(&project.root, &server.consent, budget);
    let note = (!prefilled.is_empty()).then(|| {
        json!(format!(
            "stages.attack.budget ({}) was filled in by the attack's question of devflow 0.6.2 \
             or 0.6.3, never chosen, so it no longer holds the attack; `devflow config set \
             stages.attack.budget null` takes it out of devflow.yaml",
            crate::ready::described(prefilled)
        ))
    });
    (config, note)
}

#[cfg(test)]
mod tests {
    use super::{budgeted, in_force};
    use crate::project::Project;
    use crate::server::Server;
    use devflow_engine::config::{Budget, Config};

    #[test]
    fn an_attack_after_a_review_drops_the_prefilled_budget_too() {
        let dir = tempfile::tempdir().unwrap();
        let project = Project::at(dir.path());
        let server = Server {
            consent: crate::consent::Consent::at(&dir.path().join("home")),
            ..Server::new(dir.path())
        };
        let mut config = Config::default();
        config.stages.attack.budget = Budget {
            run_cents: Some(500),
            month_cents: Some(5_000),
        };
        let (kept, note) = budgeted(&server, &project, &config);
        assert_eq!(
            kept.stages.attack.budget, config.stages.attack.budget,
            "written by hand"
        );
        assert!(note.is_none());
        let parts = ["run_usd".to_owned(), "month_usd".to_owned()];
        server
            .consent
            .keep_answer(
                &project.root,
                &crate::consent::Answered {
                    switched_on: true,
                    targets: None,
                    yeses: &["enabled"],
                    parts: &parts,
                    how: crate::consent::How::Elicitation,
                    asked_for: "attack",
                    at: std::time::SystemTime::now(),
                },
            )
            .unwrap();
        let (dropped, note) = budgeted(&server, &project, &config);
        assert!(dropped.stages.attack.budget.is_empty());
        assert!(note.unwrap().as_str().unwrap().contains("US$ 5 per attack"));
    }

    #[test]
    fn a_stack_changed_since_it_was_confirmed_is_not_in_force() {
        let kept = Some(("compose.yaml".to_owned(), "d1".to_owned()));
        assert!(in_force(kept.clone(), "compose.yaml", "d1").is_ok());
        let changed = in_force(kept.clone(), "compose.yaml", "d2").expect_err("changed");
        assert!(
            changed.contains("changed since it was confirmed"),
            "{changed}"
        );
        assert!(in_force(kept, "other.yaml", "d1").is_err(), "another file");
        assert!(
            in_force(None, "compose.yaml", "d1").is_err(),
            "never confirmed"
        );
    }
}
