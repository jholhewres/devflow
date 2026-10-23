//! `review`: a work item's change reviewed by devflow.yaml's reviewers,
//! headless on the person's own CLIs, kept in the item's run and said on the
//! item — or, without an item, a pull request, a range or a worktree
//! reviewed on demand, read where the person's checkout cannot move.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use devflow_engine::adhoc::{self, Standalone, Subject};
use devflow_engine::agents::Cli;
use devflow_engine::config::{Agent, Config};
use devflow_engine::evidence::Card;
use devflow_engine::review::{self, Asked, Git, Given, Personas};
use devflow_engine::runs;
use devflow_engine::work::WorkItems;
use devflow_engine::State;
use serde::Deserialize;
use serde_json::{json, Value};

use super::jev::Jev;
use super::{as_engine, context_of, item_here, links, redact, signed};
use crate::project::{self, Project};
use crate::server::Server;

/// How long all of one review's reviewers may take.
pub const BUDGET: Duration = Duration::from_secs(50 * 60);
/// The most of a file read to count its lines, when a finding cites one.
pub const MOST_COUNTED: u64 = 8 * 1024 * 1024;

/// The CLI on this machine that runs `agent`, or why there is none.
pub fn reach(agent: Agent) -> Result<String, String> {
    let cli = Cli::of(agent.word()).ok_or("devflow does not run this CLI headless")?;
    let program = cli.program();
    let path = std::env::var_os("PATH").unwrap_or_default();
    match devflow_engine::env::found_on(&path, program.as_ref()) {
        Some(found) => Ok(found.display().to_string()),
        None => Err("not installed".to_owned()),
    }
}

pub fn review(server: &Server, params: Value) -> Result<Value, String> {
    let project = server.project();
    let state = project.read();
    let params = as_engine(&params);
    if params.get("card").is_none_or(Value::is_null) {
        let asked =
            adhoc::standalone(&params)?.ok_or("a work item's review is asked with its `item`")?;
        return standalone(&project, &state, asked, &reach, &pull);
    }
    let config = super::config_for(&project, &state, &server.consent, "review")?;
    on_item(server, &project, config, &params, &reach)
}

type Pinned = (String, String, Vec<String>, String, u32);

/// BASE, HEAD and the diff between them.
fn pinned(root: &Path, base: Option<&str>) -> Result<Pinned, String> {
    let base = devflow_engine::git::review_base(root, base).map_err(|err| err.to_string())?;
    pinned_from(root, base)
}

/// A re-review's: from the HEAD the previous run read.
fn pinned_from(root: &Path, base: String) -> Result<Pinned, String> {
    let said = |err: devflow_engine::git::GitError| err.to_string();
    let head = devflow_engine::git::head_of(root).map_err(said)?;
    let read = devflow_engine::git::review_diff(root, &base, &head).map_err(said)?;
    Ok((base, head, read.files, read.diff, read.commits))
}

/// The brief of the epic the item was planned under.
fn brief_of(project: &Project, id: &str) -> Option<devflow_engine::brief::Brief> {
    let item = project.items().get(id).ok()??;
    let epic = project.items().get(item.parent.as_deref()?).ok()??;
    devflow_engine::brief::read(&epic.body)
}

pub fn on_item(
    server: &Server,
    project: &Project,
    config: &Config,
    params: &Value,
    reach: review::Reach,
) -> Result<Value, String> {
    let asked = review::asked(params)?;
    let item = item_here(project, &asked.card)?;
    let root = project.root.as_path();
    let runs = project.runs();
    let started = devflow_engine::started::start_of(&runs, &item.id);
    let previous = asked
        .previous
        .as_deref()
        .map(|run| review::previous_of(&runs, &item.id, run))
        .transpose()?;
    let pinned = match (&asked.run, &previous) {
        (None, Some(previous)) => Some(pinned_from(root, previous.head.clone())?),
        (None, None) => Some(pinned(root, asked.base.as_deref().or(started.as_deref()))?),
        (Some(_), _) => None,
    };
    let env = context_of(project, &item).environment();
    let evidence = super::gate::newest(&runs, &item.id, "evidence.json");
    let brief = brief_of(project, &item.id);
    let jev = Jev::of(server, project, config, Some(&item.id), &[]);
    let judging = jev
        .as_ref()
        .filter(|jev| jev.answers())
        .map(|jev| move |rubric: &str, state: &Value| jev.judge(rubric, state));
    let teams = project.teams();
    let personal = project::personal_reviewers();
    let lines_at = |commit: &str, file: &str| {
        devflow_engine::git::lines_at(root, commit, file, MOST_COUNTED)
            .map_err(|err| err.to_string())
    };
    let redacting = |text: &str| redact(text);
    let done = review::reviewed(&Given {
        root,
        runs: &runs,
        config,
        asked: &asked,
        card: Card {
            id: &item.id,
            title: &item.title,
            body: &item.body,
        },
        git: pinned.as_ref().map(|(base, head, files, diff, _)| Git {
            base,
            head,
            files,
            diff,
        }),
        brief: brief.as_ref(),
        evidence: evidence.as_ref().map(|(_, evidence)| evidence),
        env: &env,
        at: SystemTime::now(),
        budget: BUDGET,
        reach,
        redact: &redacting,
        jev: judging.as_ref().map(|judge| judge as review::Judge),
        personas: Personas {
            personal: personal.as_deref(),
            teams: &teams,
        },
        previous: previous.as_ref(),
        lines_at: &lines_at,
        retro: false,
    })?;
    let run = PathBuf::from(&done.folder);
    signed(
        project,
        &item.id,
        &review::comment(&done, &links(project, &run, &done.files())),
    );
    let mut answer = review::summary(&done);
    let commits = pinned.as_ref().map_or(0, |pinned| pinned.4);
    let ranged = asked.base.is_some() || previous.is_some();
    if let Some(warning) = review::wide(commits, ranged) {
        answer["warning"] = json!(warning);
    }
    answer["decisions"] = super::jev::decisions_of(config, jev.as_ref());
    Ok(answer)
}

/// What `gh pr view` says of a pull request.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pull {
    pub base_ref_name: String,
    pub head_ref_oid: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub body: String,
}

/// How a pull request is read, which a test answers without GitHub.
pub type Ask<'a> = &'a dyn Fn(&Path, u64) -> Result<Pull, String>;

/// A pull request of the project's GitHub repository, through `gh`.
fn pull(root: &Path, number: u64) -> Result<Pull, String> {
    let said = devflow_engine::env::command("gh")
        .args([
            "pr",
            "view",
            &number.to_string(),
            "--json",
            "baseRefName,headRefOid,title,body",
        ])
        .current_dir(root)
        .env("GH_PROMPT_DISABLED", "1")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .ok_or("gh could not read that pull request: a review of a pr needs gh signed in to the project's GitHub repository")?;
    serde_json::from_slice(&said.stdout).map_err(|err| format!("gh answered something else: {err}"))
}

/// What a review without an item runs on: the project's devflow.yaml over
/// its layers, else the person's own layer over the defaults.
pub fn config_of(state: &State) -> Result<Config, String> {
    match state {
        State::Valid(_, config) => Ok((**config).clone()),
        State::Missing => devflow_engine::layers::personal_only(&project::home())
            .map_err(|invalid| invalid.to_string()),
        State::Invalid(..) => Err("devflow.yaml does not read: `status` says why".to_owned()),
    }
}

/// `path` when it is the project's root or one of its git worktrees.
fn worktree_of(root: &Path, path: &str) -> Result<PathBuf, String> {
    let refused = || format!("{path} is not a worktree of this project");
    let at = Path::new(path).canonicalize().map_err(|_| refused())?;
    let listed = devflow_engine::git::worktrees(root).map_err(|err| err.to_string())?;
    listed
        .iter()
        .filter_map(|tree| Path::new(tree).canonicalize().ok())
        .find(|tree| *tree == at)
        .ok_or_else(refused)
}

/// A detached worktree, removed when the review is done with it.
struct Detached<'a> {
    root: &'a Path,
    at: PathBuf,
}

impl Drop for Detached<'_> {
    fn drop(&mut self) {
        devflow_engine::git::remove_detached(self.root, &self.at);
    }
}

struct Resolved {
    base: String,
    head: String,
    title: String,
    criteria: Vec<String>,
    tree: Option<PathBuf>,
}

/// A plain branch name, as a pull request's base must be.
fn plain_branch(name: &str) -> bool {
    devflow_engine::git::plain_revision(name)
        && !name.contains("..")
        && !name.ends_with('/')
        && !name.contains(['~', '^', ':', '?', '*', '[', '\\'])
}

fn resolved(root: &Path, asked: &Standalone, ask: Ask) -> Result<Resolved, String> {
    use devflow_engine::git;
    let said = |err: git::GitError| err.to_string();
    match &asked.subject {
        Subject::Pr(number) => {
            let pull = ask(root, *number)?;
            if !plain_branch(&pull.base_ref_name) {
                return Err("the pull request's base is not a plain branch".to_owned());
            }
            if git::commit_of(root, &pull.head_ref_oid).is_err() {
                git::fetch_pull(root, *number).map_err(said)?;
            }
            let head = git::commit_of(root, &pull.head_ref_oid).map_err(said)?;
            let base = git::merge_base(root, &format!("origin/{}", pull.base_ref_name), &head)
                .or_else(|_| git::merge_base(root, &pull.base_ref_name, &head))
                .map_err(said)?;
            Ok(Resolved {
                base,
                head,
                title: format!("PR #{number}: {}", pull.title),
                criteria: adhoc::pr_criteria(&asked.criteria, &pull.title, &pull.body),
                tree: None,
            })
        }
        Subject::Range { base, head } => {
            let head = git::commit_of(root, head).map_err(said)?;
            Ok(Resolved {
                base: git::merge_base(root, base, &head).map_err(said)?,
                title: format!("{base}..{}", &head[..12.min(head.len())]),
                head,
                criteria: asked.criteria.clone(),
                tree: None,
            })
        }
        Subject::Path { path, base } => {
            let tree = worktree_of(root, path)?;
            Ok(Resolved {
                base: git::review_base(&tree, base.as_deref()).map_err(said)?,
                head: git::head_of(&tree).map_err(said)?,
                title: format!("the worktree {}", tree.display()),
                criteria: asked.criteria.clone(),
                tree: Some(tree),
            })
        }
    }
}

pub fn standalone(
    project: &Project,
    state: &State,
    asked: Standalone,
    reach: review::Reach,
    ask: Ask,
) -> Result<Value, String> {
    let config = config_of(state)?;
    let root = project.root.as_path();
    let resolved = match (&asked.subject, &asked.run) {
        (Subject::Pr(_), Some(_)) => None,
        _ => Some(resolved(root, &asked, ask)?),
    };
    let label = adhoc::label(
        &asked.subject,
        resolved.as_ref().map_or("", |at| at.base.as_str()),
        resolved.as_ref().map_or("", |at| at.head.as_str()),
    );
    let at = SystemTime::now();
    let mut detached = None;
    let reading = match &resolved {
        Some(Resolved {
            tree: Some(tree), ..
        }) => tree.clone(),
        Some(resolved) if asked.run.is_none() => {
            let tree = project
                .review_trees()
                .join(format!("{label}-{}", runs::stamp(at)));
            devflow_engine::git::add_detached(root, &tree, &resolved.head)
                .map_err(|err| err.to_string())?;
            detached = Some(Detached {
                root,
                at: tree.clone(),
            });
            tree
        }
        _ => root.to_path_buf(),
    };
    let git = match (&resolved, &asked.run) {
        (Some(resolved), None) => Some(
            devflow_engine::git::review_diff(&reading, &resolved.base, &resolved.head)
                .map_err(|err| err.to_string())?,
        ),
        _ => None,
    };
    let criteria = resolved
        .as_ref()
        .map_or_else(Vec::new, |at| at.criteria.clone());
    let body = adhoc::body_of(&criteria);
    let title = resolved
        .as_ref()
        .map_or_else(|| label.clone(), |at| at.title.clone());
    let runs = project.reviews(&reading);
    let teams = project.teams();
    let personal = project::personal_reviewers();
    let lines_at = |commit: &str, file: &str| {
        devflow_engine::git::lines_at(root, commit, file, MOST_COUNTED)
            .map_err(|err| err.to_string())
    };
    let redacting = |text: &str| redact(text);
    let as_item = Asked {
        card: label.clone(),
        base: None,
        run: asked.run.clone(),
        reports: asked.reports.clone(),
        previous: None,
        verified: Vec::new(),
    };
    let done = review::reviewed(&Given {
        root: &reading,
        runs: &runs,
        config: &config,
        asked: &as_item,
        card: Card {
            id: &label,
            title: &title,
            body: &body,
        },
        git: match (&resolved, &git) {
            (Some(resolved), Some(read)) => Some(Git {
                base: &resolved.base,
                head: &resolved.head,
                files: &read.files,
                diff: &read.diff,
            }),
            _ => None,
        },
        brief: None,
        evidence: None,
        env: &[],
        at,
        budget: BUDGET,
        reach,
        redact: &redacting,
        jev: None,
        personas: Personas {
            personal: personal.as_deref(),
            teams: &teams,
        },
        previous: None,
        lines_at: &lines_at,
        retro: asked.retro,
    });
    let read_detached = detached
        .as_ref()
        .and(resolved.as_ref())
        .map(|at| at.head.clone());
    drop(detached);
    let done = done?;
    runs::prune(&runs.home.join(&label), runs::KEPT);
    let mut answer = review::summary(&done);
    if let Some(fields) = answer.as_object_mut() {
        fields.remove("card");
    }
    answer["reviewed"] = json!(label);
    answer["next"] = json!(adhoc::next(
        &asked.subject,
        &label,
        &done.stamp,
        &done.pending,
        read_detached.as_deref(),
        done.retro
    ));
    Ok(answer)
}
