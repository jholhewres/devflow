//! `evidence`: a card's checks run through devpit's steps
//! runner, the card's context in their environment and never in their
//! command; their reports read; and what they prove kept in the run's folder
//! (`runs.rs`), summed up for the agent and for the card.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use crate::runner::report::{self, Case, Outcome, Reported};
use crate::runner::Context;
use crate::verdict::{verdict, Report, RunState, Verdict};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::config::{Check, Config, Report as Format};
use crate::dialect::Dialect;
use crate::fresh::Tree;
use crate::plan::PREFIX;
use crate::runs::{self, Attached, Media, Runs};

/// The fields the tool takes, as the execution and completion skills send
/// them; `project` is an orchestrator's, as on every board tool.
pub const FIELDS: [&str; 4] = ["card", "checks", "criteria", "red"];
/// The field that runs the checks even when a green run of the same commit
/// and tracked files could be reused.
pub const FRESH: &str = "fresh";

fn shape(said: &Dialect) -> String {
    format!(
        "{{ {}, checks?: [name], criteria?: [{{ criterion, tests?: [test id], proof?: {{ kind: screenshot|e2e|artifact, path }} }}], red?: [{{ test, failure }}] }}",
        said.item_field
    )
}
const MOST_CRITERIA: usize = 100;
const MOST_TESTS: usize = 50;
const MOST_RED: usize = 200;
const LONGEST: usize = 1000;
/// The lines of a check's output the answer ends with when it did not pass.
const TAIL: usize = 5;
/// The failures the answer names per check; the log and evidence.json have the rest.
const NAMED: usize = 5;
/// The files the card's comment links; the artifacts have the rest.
const LINKED: usize = 20;

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mapped {
    pub criterion: String,
    #[serde(default)]
    pub tests: Vec<String>,
    /// A file that shows it, for what no test runner here can: a screenshot.
    #[serde(default)]
    pub proof: Option<Proof>,
}

/// What a proof is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofKind {
    Screenshot,
    E2e,
    Artifact,
}

impl ProofKind {
    pub fn word(self) -> &'static str {
        match self {
            ProofKind::Screenshot => "screenshot",
            ProofKind::E2e => "e2e",
            ProofKind::Artifact => "artifact",
        }
    }
}

/// A criterion's proof: a file in the run's folder or the checkout.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub kind: ProofKind,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Red {
    pub test: String,
    pub failure: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Asked {
    pub card: String,
    #[serde(default)]
    pub checks: Option<Vec<String>>,
    #[serde(default)]
    pub criteria: Vec<Mapped>,
    #[serde(default)]
    pub red: Vec<Red>,
    /// Run the checks even when a green run can be reused.
    #[serde(default)]
    pub fresh: bool,
}

/// The tool's input, refused with the shape it takes when it is not that.
pub fn asked(params: &Value) -> Result<Asked, String> {
    asked_in(&Dialect::DEVFLOW, params)
}

/// [`asked`], refused in `dialect`'s words.
pub fn asked_in(dialect: &Dialect, params: &Value) -> Result<Asked, String> {
    let params = &crate::work::as_card(params);
    let shape = shape(dialect);
    let extra = params.as_object().and_then(|fields| {
        fields.keys().find(|key| {
            !FIELDS.contains(&key.as_str()) && !["project", FRESH].contains(&key.as_str())
        })
    });
    if let Some(extra) = extra {
        return Err(format!(
            "`{extra}` is not a field of the evidence: it takes {shape}"
        ));
    }
    let asked: Asked = serde_json::from_value(params.clone())
        .map_err(|why| format!("the evidence is {shape}: {why}"))?;
    if asked.card.trim().is_empty() {
        return Err(format!(
            "which {}? pass its id as `{}`",
            dialect.item, dialect.item_field
        ));
    }
    let texts = asked
        .criteria
        .iter()
        .flat_map(|one| {
            std::iter::once(&one.criterion)
                .chain(&one.tests)
                .chain(one.proof.as_ref().map(|proof| &proof.path))
        })
        .chain(asked.red.iter().flat_map(|one| [&one.test, &one.failure]))
        .chain(asked.checks.iter().flatten());
    let too_many = asked.criteria.len() > MOST_CRITERIA
        || asked.red.len() > MOST_RED
        || asked
            .criteria
            .iter()
            .any(|one| one.tests.len() > MOST_TESTS);
    if too_many {
        return Err(format!(
            "at most {MOST_CRITERIA} criteria of {MOST_TESTS} tests each, and {MOST_RED} red tests"
        ));
    }
    if texts.into_iter().any(|text| text.chars().count() > LONGEST) {
        return Err(format!(
            "each criterion, test, proof path and failure is at most {LONGEST} characters: quote the failing line"
        ));
    }
    Ok(asked)
}

/// The checks to run: those `named`, in devflow.yaml's order, or every one.
pub fn chosen<'a>(checks: &'a [Check], named: Option<&[String]>) -> Result<Vec<&'a Check>, String> {
    chosen_in(&Dialect::DEVFLOW, checks, named)
}

/// [`chosen`], refused in `dialect`'s words.
pub fn chosen_in<'a>(
    dialect: &Dialect,
    checks: &'a [Check],
    named: Option<&[String]>,
) -> Result<Vec<&'a Check>, String> {
    if checks.is_empty() {
        return Err(format!(
            "devflow.yaml configures no checks under stages.execution.checks: {} adds one",
            dialect.tools.set
        ));
    }
    let Some(named) = named.filter(|named| !named.is_empty()) else {
        return Ok(checks.iter().collect());
    };
    if let Some(unknown) = named
        .iter()
        .find(|name| !checks.iter().any(|check| &check.name == *name))
    {
        let all: Vec<&str> = checks.iter().map(|check| check.name.as_str()).collect();
        return Err(format!(
            "`{unknown}` is not a check in devflow.yaml, which has {}",
            all.join(", ")
        ));
    }
    Ok(checks
        .iter()
        .filter(|check| named.contains(&check.name))
        .collect())
}

/// How one check went.
#[derive(Debug, Clone, PartialEq)]
pub struct Ran {
    pub name: String,
    pub verdict: Verdict,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub seconds: f64,
    pub reported: Option<Reported>,
    /// Paths relative to the run's folder.
    pub log: Option<String>,
    pub reports: Vec<String>,
    pub media: Media,
    /// The output's last lines, for a check that did not pass.
    pub tail: Vec<String>,
    /// Why it never started.
    pub not_run: Option<String>,
}

impl Ran {
    fn not_run(name: &str, why: String) -> Ran {
        Ran {
            name: name.to_owned(),
            verdict: Verdict::NotRun,
            exit_code: None,
            timed_out: false,
            seconds: 0.0,
            reported: None,
            log: None,
            reports: Vec::new(),
            media: Media::default(),
            tail: Vec::new(),
            not_run: Some(why),
        }
    }
}

/// The word a verdict is said with.
pub fn said(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Passed => "passed",
        Verdict::Failed => "failed",
        Verdict::Inconclusive => "inconclusive",
        Verdict::NotRun => "not run",
    }
}

/// How long a check's `requires` probe has.
const PROBE: Duration = Duration::from_secs(30);

/// The shell's exit for a command it could not find.
const NOT_FOUND: i32 = 127;

/// A check's verdict. One that writes a report is held to a command step's
/// rule, where exit zero with no report is not a pass; one set to `report:
/// none` never writes one, so its exit code is all it says and it decides.
pub fn checked(
    format: Format,
    state: RunState,
    read: Option<Report>,
    exit: Option<i32>,
) -> Verdict {
    if format != Format::Nothing {
        return verdict(state, read);
    }
    match (state, read, exit) {
        (_, Some(read), _) if read.failed > 0 => Verdict::Failed,
        (_, _, Some(NOT_FOUND)) => Verdict::NotRun,
        (RunState::Ok, ..) => Verdict::Passed,
        _ => Verdict::Failed,
    }
}

/// The lock `name` in `locks`, waited for up to `timeout`, with its file.
/// It is held until the file is dropped, and a process that dies lets it go.
pub fn locked(
    locks: &Path,
    name: &str,
    timeout: Duration,
) -> Result<(std::fs::File, PathBuf), String> {
    std::fs::create_dir_all(locks).map_err(|err| err.to_string())?;
    let path = locks.join(format!("{name}.lock"));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|err| err.to_string())?;
    let started = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => return Ok((file, path)),
            Err(std::fs::TryLockError::WouldBlock) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(format!(
                    "another check held the lock `{name}` for all the time the evidence had"
                ))
            }
            Err(std::fs::TryLockError::Error(err)) => return Err(err.to_string()),
        }
    }
}

/// Why the probe `requires` says a check cannot run now, or `None` when it
/// passed: a database that is down is not the code's failure.
pub fn prerequisite_failed(
    requires: &str,
    cwd: &Path,
    context: &Context,
    timeout: Duration,
) -> Option<String> {
    let ended = crate::runner::run(requires, cwd, context, Some(timeout), |_| {}, |_| {});
    let how = match ended {
        Err(err) => format!("it did not start: {err}"),
        Ok(ended) if ended.timed_out => format!("it took over {}s", timeout.as_secs()),
        Ok(ended) => match ended.exit_code {
            Some(0) => return None,
            Some(code) => format!("it exited {code}"),
            None => "it was stopped".to_owned(),
        },
    };
    Some(format!("prerequisite failed: `{requires}`: {how}"))
}

/// Runs one check through the steps runner from `cwd`: the card's context in
/// its environment, `$DEVFLOW_REPORT_DIR` its own folder of the run, and its
/// verdict [`checked`]. Its `exclusive` lock is held from `locks` for the
/// whole run, and its `requires` probe must pass first.
pub fn run_check(
    check: &Check,
    cwd: &Path,
    run: &Path,
    locks: &Path,
    context: &Context,
    timeout: Duration,
    redact: &dyn Fn(&str) -> String,
) -> Ran {
    let folder = run.join(&check.name);
    let mut context = context.clone();
    context.report_dir = folder.display().to_string();
    let waited = Instant::now();
    let _held = match &check.exclusive {
        Some(name) => match locked(locks, name, timeout) {
            Ok((file, path)) => {
                context
                    .locks
                    .push((name.clone(), path.display().to_string()));
                Some(file)
            }
            Err(why) => return Ran::not_run(&check.name, why),
        },
        None => None,
    };
    let timeout = timeout.saturating_sub(waited.elapsed());
    if timeout < Duration::from_secs(1) {
        return Ran::not_run(
            &check.name,
            "waiting for its lock took all the time".to_owned(),
        );
    }
    if let Some(requires) = &check.requires {
        if let Some(why) = prerequisite_failed(requires, cwd, &context, timeout.min(PROBE)) {
            return Ran::not_run(&check.name, why);
        }
    }
    let mut output = String::new();
    let ended = std::fs::create_dir(&folder)
        .map_err(|err| err.to_string())
        .and_then(|()| {
            crate::runner::run(
                &check.run,
                cwd,
                &context,
                Some(timeout),
                |_| {},
                |said| {
                    output.push_str(&said.text);
                    output.push_str(if said.cut { " … (line cut)\n" } else { "\n" });
                },
            )
            .map_err(|err| err.to_string())
        });
    let ended = match ended {
        Ok(ended) => ended,
        Err(why) => return Ran::not_run(&check.name, why),
    };
    let mut reported = report::read_cases(
        Some(&folder),
        (!ended.output_cut).then_some(output.as_str()),
        cwd,
    );
    // Failure text is output too: what devpit knows to be secret comes out.
    for failure in reported
        .iter_mut()
        .flat_map(|read| read.tested.failures.iter_mut())
    {
        failure.name = redact(&failure.name);
        failure.message = failure.message.as_deref().map(redact);
    }
    let state = if ended.exit_code == Some(0) && !ended.timed_out {
        RunState::Ok
    } else {
        RunState::Failed
    };
    let read = reported.as_ref().map(|read| Report {
        passed: read.tested.passed,
        failed: read.tested.failed,
    });
    if ended.timed_out {
        output.push_str(&format!(
            "— stopped after {}s, all the time the evidence had left\n",
            timeout.as_secs()
        ));
    }
    let output = redact(&output);
    let log = format!("{}.log", check.name);
    let lines: Vec<&str> = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    let verdict = checked(check.report, state, read, ended.exit_code);
    Ran {
        name: check.name.clone(),
        verdict,
        exit_code: ended.exit_code,
        timed_out: ended.timed_out,
        seconds: ended.duration_ms as f64 / 1000.0,
        reports: report_files(&folder, &check.name, redact),
        media: runs::gather(run, &check.name, &check.evidence),
        log: std::fs::write(run.join(&log), &output)
            .is_ok()
            .then_some(log),
        tail: lines[lines.len().saturating_sub(TAIL)..]
            .iter()
            .map(|line| line.chars().take(300).collect())
            .collect(),
        reported,
        not_run: (verdict == Verdict::NotRun).then(|| {
            format!("exit {NOT_FOUND}, the shell found no such command: install it or fix `run` in devflow.yaml")
        }),
    }
}

/// The reports a check left at the top of its folder, as `report` reads them.
/// Each is written again without what devpit knows to be secret: a report is
/// kept and attached whole.
fn report_files(folder: &Path, check: &str, redact: &dyn Fn(&str) -> String) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(folder) else {
        return Vec::new();
    };
    let mut found: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_type().is_ok_and(|kind| kind.is_file())
                && entry
                    .metadata()
                    .is_ok_and(|meta| meta.len() <= report::MOST_REPORT)
        })
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.ends_with(".xml") || name.ends_with(".json"))
        .collect();
    found.sort();
    found.truncate(report::MOST_REPORTS);
    for name in &found {
        let path = folder.join(name);
        if let Ok(text) = std::fs::read_to_string(&path) {
            let kept = redact(&text);
            if kept != text {
                let _ = std::fs::write(&path, kept);
            }
        }
    }
    found
        .into_iter()
        .map(|name| format!("{check}/{name}"))
        .collect()
}

/// A criterion and how each of its tests ended in this run.
#[derive(Debug, Clone, PartialEq)]
pub struct Seen {
    pub criterion: String,
    /// Whether the card's body lists it under its acceptance criteria.
    pub on_card: bool,
    pub tests: Vec<(String, Option<Outcome>)>,
    /// Its proof, and whether the file is there.
    pub proof: Option<(Proof, bool)>,
}

impl Seen {
    /// It named a test or a proof, every test ran and passed, and the proof
    /// is there: a screenshot never excuses a red test.
    pub fn green(&self) -> bool {
        (!self.tests.is_empty() || self.proof.is_some())
            && self
                .tests
                .iter()
                .all(|(_, ended)| *ended == Some(Outcome::Passed))
            && self.proof.as_ref().is_none_or(|(_, there)| *there)
    }
}

/// Whether a proof's file is there, in the run's folder or else the
/// checkout: resolved through symlinks and never outside either.
pub fn proved(proof: &Proof, run: &Path, root: &Path) -> bool {
    [run, root]
        .iter()
        .any(|base| crate::fsguard::resolve(base, &proof.path).is_ok_and(|found| found.is_file()))
}

/// A test the agent saw fail, and how it ended now.
#[derive(Debug, Clone, PartialEq)]
pub struct RedSeen {
    pub test: String,
    pub failure: String,
    pub now: Option<Outcome>,
}

/// The card's E2E spec: where the execution skill writes it, and whether it is there.
#[derive(Debug, Clone, PartialEq)]
pub struct Spec {
    pub path: String,
    pub exists: bool,
}

/// `<e2e_dir>/<card>-<slug>.spec.ts`, the slug the card's title in kebab case.
pub fn spec_path(e2e_dir: &str, card: &str, title: &str) -> String {
    let title = title.strip_prefix(PREFIX).unwrap_or(title);
    let mut slug = String::new();
    for ch in title.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch);
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    slug.truncate(60);
    match slug.trim_end_matches('-') {
        "" => format!("{e2e_dir}/{card}.spec.ts"),
        slug => format!("{e2e_dir}/{card}-{slug}.spec.ts"),
    }
}

/// The card a run is evidence for.
pub struct Card<'a> {
    pub id: &'a str,
    pub title: &'a str,
    pub body: &'a str,
}

/// One run of a card's checks, and what it showed.
#[derive(Debug, Clone, PartialEq)]
pub struct Evidence {
    /// The words its record, summary and comment are in.
    pub dialect: &'static Dialect,
    pub card: String,
    /// The run's name, its time.
    pub stamp: String,
    /// Where the run is, in devpit's folder for the project.
    pub folder: String,
    pub checks: Vec<Ran>,
    pub criteria: Vec<Seen>,
    /// The card's criteria no test was named for.
    pub not_mapped: Vec<String>,
    pub red: Vec<RedSeen>,
    pub spec: Option<Spec>,
    /// Older runs of the card removed to keep [`runs::KEPT`].
    pub pruned: Vec<String>,
    /// The commit and tracked files the checks read; `None` outside git.
    pub tree: Option<Tree>,
    /// The run whose checks' results this one took, at the same tree.
    pub reused_from: Option<String>,
    /// A card with no criteria read: the checkboxes it has under another
    /// heading, the one holding the most.
    pub criteria_unread: Option<crate::criteria::Unread>,
}

impl Evidence {
    /// Every check ran and passed.
    pub fn green(&self) -> bool {
        !self.checks.is_empty() && self.checks.iter().all(|ran| ran.verdict == Verdict::Passed)
    }

    /// The files worth attaching to the card, relative to the run's folder.
    pub fn files(&self, run: &Path) -> Vec<String> {
        let mut files: Vec<String> = self
            .checks
            .iter()
            .flat_map(|ran| {
                ran.reports
                    .iter()
                    .chain(&ran.log)
                    .chain(&ran.media.screenshots)
                    .chain(&ran.media.video)
                    .cloned()
            })
            .collect();
        // findings.json and gate.json are the review's and the gate's, when they ran first.
        for kept in ["evidence.json", "findings.json", "gate.json"] {
            if run.join(kept).is_file() {
                files.push(kept.to_owned());
            }
        }
        files
    }
}

/// Text compared the way a person reads it: trimmed, one space between words.
pub(crate) fn plain(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// What a run of a card's checks is given.
pub struct Given<'a> {
    pub dialect: &'static Dialect,
    /// The checkout the checks run in.
    pub root: &'a Path,
    /// Where the run is kept.
    pub runs: &'a Runs,
    /// Where the project's `exclusive` locks are, in devpit's folder for it.
    pub locks: &'a Path,
    pub config: &'a Config,
    pub asked: &'a Asked,
    pub card: Card<'a>,
    pub context: &'a Context,
    /// All the checks together have this long.
    pub budget: Duration,
    /// Takes out of a text what devpit knows to be secret.
    pub redact: &'a dyn Fn(&str) -> String,
    pub at: SystemTime,
}

/// Runs the checks `given` names for its card, and keeps the run in
/// devpit's folder, `<card>/<time>/` with `evidence.json`; older runs past
/// [`runs::KEPT`] go.
pub fn gathered(given: &Given) -> Result<Evidence, String> {
    let Given {
        dialect,
        root,
        runs: kept,
        locks,
        config,
        asked,
        card,
        context,
        budget,
        redact,
        at,
    } = given;
    let (root, budget, redact) = (*root, *budget, *redact);
    let runnable = config.stages.execution.runnable(asked.checks.as_deref());
    let checks = chosen_in(dialect, &runnable, asked.checks.as_deref())?;
    let tree = crate::fresh::tree_of(root);
    let reusable = tree
        .as_ref()
        .filter(|_| !asked.fresh)
        .and_then(|tree| reusable(root, kept, card.id, tree, &checks));
    let run = kept.fresh(card.id, *at)?;
    let folder = run.display().to_string();
    let started = Instant::now();
    let ran: Vec<Ran> = checks
        .iter()
        .map(|check| {
            let left = budget.saturating_sub(started.elapsed());
            if let Some((_, from, record)) = &reusable {
                reused(check, from, record, &run, root)
            } else if left < Duration::from_secs(1) {
                Ran::not_run(
                    &check.name,
                    "the checks before it took all the time".to_owned(),
                )
            } else {
                run_check(check, root, &run, locks, context, left, redact)
            }
        })
        .collect();
    let cases: Vec<Case> = ran
        .iter()
        .filter_map(|ran| ran.reported.as_ref())
        .flat_map(|read| read.cases.iter().cloned())
        .collect();
    let on_card: Vec<String> = crate::criteria::criteria(card.body)
        .into_iter()
        .map(|one| plain(&one.text))
        .collect();
    let criteria_unread = on_card.is_empty().then(|| most_unread(card.body)).flatten();
    let criteria: Vec<Seen> = asked
        .criteria
        .iter()
        .map(|mapped| Seen {
            on_card: on_card.contains(&plain(&mapped.criterion)),
            criterion: mapped.criterion.clone(),
            tests: mapped
                .tests
                .iter()
                .map(|test| (test.clone(), report::outcome_of(test, &cases)))
                .collect(),
            proof: mapped
                .proof
                .as_ref()
                .map(|proof| (proof.clone(), proved(proof, &run, root))),
        })
        .collect();
    let not_mapped = on_card
        .iter()
        .filter(|text| !criteria.iter().any(|seen| plain(&seen.criterion) == **text))
        .cloned()
        .collect();
    let spec = config
        .stages
        .execution
        .checks
        .iter()
        .any(|check| check.name == "e2e")
        .then(|| {
            let path = spec_path(&config.stages.execution.e2e_dir, card.id, card.title);
            Spec {
                exists: crate::fsguard::resolve(root, &path).is_ok_and(|found| found.is_file()),
                path,
            }
        });
    let mut evidence = Evidence {
        dialect,
        card: card.id.to_owned(),
        stamp: run
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned(),
        folder,
        checks: ran,
        criteria,
        not_mapped,
        red: asked
            .red
            .iter()
            .map(|red| RedSeen {
                test: red.test.clone(),
                failure: redact(&red.failure),
                now: report::outcome_of(&red.test, &cases),
            })
            .collect(),
        spec,
        pruned: Vec::new(),
        tree,
        reused_from: reusable.map(|(name, ..)| name),
        criteria_unread,
    };
    let record = serde_json::to_string_pretty(&recorded(&evidence)).unwrap_or_default();
    std::fs::write(run.join("evidence.json"), record).map_err(|err| err.to_string())?;
    if let Some(parent) = run.parent() {
        evidence.pruned = runs::prune(parent, runs::KEPT);
    }
    Ok(evidence)
}

/// The heading holding the most checkboxes that are not criteria, the first
/// of those that hold as many.
fn most_unread(body: &str) -> Option<crate::criteria::Unread> {
    crate::criteria::unread(body)
        .into_iter()
        .rev()
        .max_by_key(|group| group.count)
}

/// What a card with checkboxes under another heading is told.
pub fn unread_said(said: &Dialect, unread: &crate::criteria::Unread) -> String {
    let (item, heading) = (said.item, crate::criteria::HEADING);
    let under = if unread.heading.is_empty() {
        "under no heading".to_owned()
    } else {
        format!("under `## {}`", unread.heading)
    };
    format!(
        "the {item} has no `## {heading}`; {} checkboxes {under} were not read as criteria",
        unread.count
    )
}

fn unread_json(unread: &crate::criteria::Unread) -> Value {
    json!({ "heading": unread.heading, "count": unread.count })
}

/// The newest run of the card, when it was green at `tree`, passed every
/// check in `checks` and no untracked file but a proof was written since:
/// its name, its folder and its evidence.json.
fn reusable(
    root: &Path,
    kept: &Runs,
    card: &str,
    tree: &Tree,
    checks: &[&Check],
) -> Option<(String, PathBuf, Value)> {
    let (name, at) = kept.newest_with(card, "evidence.json")?;
    let record: Value = serde_json::from_slice(&within(&at, MOST_RECORD)?).ok()?;
    let passed = |wanted: &&Check| {
        record["checks"].as_array().is_some_and(|ran| {
            ran.iter()
                .any(|one| one["name"] == wanted.name.as_str() && one["result"] == "passed")
        })
    };
    let home = kept
        .home
        .strip_prefix(root)
        .ok()
        .and_then(Path::to_str)
        .filter(|home| !home.is_empty())
        .map(|home| format!("{home}/"));
    let ours: Vec<&str> = [".devflow/", ".devpit/"]
        .into_iter()
        .chain(home.as_deref())
        .collect();
    let same = record["green"] == true
        && Tree::of(&record).as_ref() == Some(tree)
        && checks.iter().all(passed)
        && crate::fresh::holds(root, &name, &record, &ours);
    let folder = at.parent()?.to_path_buf();
    same.then_some((name, folder, record))
}

fn words(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// The evidence.json of a run read for reuse, at most.
const MOST_RECORD: u64 = 4 * 1024 * 1024;

/// The file `path`, when it is at most `ceiling` bytes.
fn within(path: &Path, ceiling: u64) -> Option<Vec<u8>> {
    let file = std::fs::File::open(path).ok()?;
    crate::fsguard::read_within(file, ceiling).ok()?
}

/// Copies `relative` from run `from` into run `to`, a folder whole; a link
/// is never copied nor followed.
fn copied(from: &Path, to: &Path, relative: &str) {
    if crate::fsguard::resolve(from, relative).is_err() {
        return;
    }
    let Ok(target) = crate::fsguard::resolve_new(to, relative) else {
        return;
    };
    let source = from.join(relative);
    let Ok(kind) = std::fs::symlink_metadata(&source).map(|meta| meta.file_type()) else {
        return;
    };
    if kind.is_file() {
        if let Some(parent) = target.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::copy(&source, &target);
    } else if kind.is_dir() {
        let _ = std::fs::create_dir_all(&target);
        for entry in std::fs::read_dir(&source).into_iter().flatten().flatten() {
            if let Some(name) = entry.file_name().to_str() {
                copied(from, to, &format!("{relative}/{name}"));
            }
        }
    }
}

/// A check's result taken from run `from`, its folder, log and media copied
/// into `run` and its report read again there: it is not run.
fn reused(check: &Check, from: &Path, record: &Value, run: &Path, root: &Path) -> Ran {
    let said = record["checks"]
        .as_array()
        .and_then(|ran| ran.iter().find(|one| one["name"] == check.name.as_str()))
        .cloned()
        .unwrap_or_default();
    let log = said["log"].as_str().map(str::to_owned);
    let (screenshots, video) = (words(&said["screenshots"]), words(&said["video"]));
    for relative in std::iter::once(&check.name)
        .chain(&log)
        .chain(&screenshots)
        .chain(&video)
    {
        copied(from, run, relative);
    }
    let printed = log
        .as_ref()
        .and_then(|log| crate::fsguard::resolve(run, log).ok())
        .and_then(|at| within(&at, report::MOST_REPORT))
        .map(|raw| String::from_utf8_lossy(&raw).into_owned());
    Ran {
        name: check.name.clone(),
        verdict: Verdict::Passed,
        exit_code: said["exit"]
            .as_i64()
            .and_then(|code| i32::try_from(code).ok()),
        timed_out: false,
        seconds: said["seconds"].as_f64().unwrap_or_default(),
        reported: report::read_cases(Some(&run.join(&check.name)), printed.as_deref(), root),
        log,
        reports: words(&said["reports"]),
        media: Media { screenshots, video },
        tail: Vec::new(),
        not_run: None,
    }
}

/// How a test ended, from the word evidence.json says it with.
fn outcome_from(word: &str) -> Option<Outcome> {
    [Outcome::Passed, Outcome::Failed, Outcome::Skipped]
        .into_iter()
        .find(|outcome| outcome.word() == word)
}

/// `evidence` with each criterion's proof looked for again now, in `run`'s
/// folder or the checkout, and its green said again by [`Seen::green`] from
/// the tests it recorded: a proof written after the run counts. A run that
/// recorded no tree (before v0.2.2) is judged as it was written.
pub fn rechecked(evidence: &Value, run: &Path, root: &Path) -> Value {
    let mut evidence = evidence.clone();
    if Tree::of(&evidence).is_none() {
        return evidence;
    }
    let Some(criteria) = evidence.get_mut("criteria").and_then(Value::as_array_mut) else {
        return evidence;
    };
    for seen in criteria {
        let proof = seen["proof"].as_object().and_then(|proof| {
            let kind = proof.get("kind")?.as_str()?;
            let kind = [ProofKind::Screenshot, ProofKind::E2e, ProofKind::Artifact]
                .into_iter()
                .find(|one| one.word() == kind)?;
            let path = proof.get("path")?.as_str()?.to_owned();
            Some(Proof { kind, path })
        });
        let there = proof.as_ref().map(|proof| proved(proof, run, root));
        let again = Seen {
            criterion: String::new(),
            on_card: false,
            tests: seen["tests"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|test| {
                    let ended = test["result"].as_str().and_then(outcome_from);
                    (String::new(), ended)
                })
                .collect(),
            proof: proof.zip(there),
        };
        if let Some(there) = there {
            seen["proof"]["exists"] = json!(there);
        }
        seen["green"] = json!(again.green());
    }
    evidence
}

fn outcome_word(ended: Option<Outcome>) -> &'static str {
    ended.map_or("not found", Outcome::word)
}

fn counts(ran: &Ran) -> Value {
    let tested = ran.reported.as_ref().map(|read| &read.tested);
    json!({
        "passed": tested.map(|tested| tested.passed),
        "failed": tested.map(|tested| tested.failed),
        "skipped": tested.map(|tested| tested.skipped),
    })
}

/// `evidence.json`: everything the run showed, for the gate and the review.
pub fn recorded(evidence: &Evidence) -> Value {
    let mut record = record_of(evidence);
    if let Some(tree) = &evidence.tree {
        record["head"] = json!(tree.head);
        record["tree"] = json!(tree.tracked);
    }
    if let Some(from) = &evidence.reused_from {
        record["reused_from"] = json!(from);
    }
    if let Some(unread) = &evidence.criteria_unread {
        record["criteria_unread"] = unread_json(unread);
    }
    record
}

fn record_of(evidence: &Evidence) -> Value {
    let dialect = evidence.dialect;
    json!({
        dialect.product: crate::skills::made_by_in(dialect, &["devflow-execution", "devflow-completion"]),
        "card": evidence.card,
        "at": evidence.stamp,
        "green": evidence.green(),
        "checks": evidence.checks.iter().map(|ran| json!({
            "name": ran.name,
            "result": said(ran.verdict),
            "exit": ran.exit_code,
            "timed_out": ran.timed_out,
            "seconds": ran.seconds,
            "tests": counts(ran),
            "read_from": ran.reported.as_ref().map(|read| &read.tested.read_from),
            "failures": ran.reported.as_ref().map(|read| &read.tested.failures),
            "reports": ran.reports,
            "log": ran.log,
            "screenshots": ran.media.screenshots,
            "video": ran.media.video,
            "not_run": ran.not_run,
        })).collect::<Vec<_>>(),
        "criteria": criteria_json(evidence),
        "not_mapped": evidence.not_mapped,
        "red": evidence.red.iter().map(|red| json!({
            "test": red.test, "failure": red.failure, "now": outcome_word(red.now),
        })).collect::<Vec<_>>(),
        "spec": evidence.spec.as_ref().map(|spec| json!({ "path": spec.path, "exists": spec.exists })),
    })
}

fn criteria_json(evidence: &Evidence) -> Vec<Value> {
    evidence
        .criteria
        .iter()
        .map(|seen| {
            json!({
                "criterion": seen.criterion,
                "on_card": seen.on_card,
                "green": seen.green(),
                "tests": seen.tests.iter().map(|(test, ended)| json!({
                    "test": test, "result": outcome_word(*ended),
                })).collect::<Vec<_>>(),
                "proof": seen.proof.as_ref().map(|(proof, there)| json!({
                    "kind": proof.kind.word(), "path": proof.path, "exists": there,
                })),
            })
        })
        .collect()
}

/// What the agent is answered: each check passed or not, its counts and the
/// paths, and no log.
pub fn summary(evidence: &Evidence, attached: &Attached, under: &str) -> Value {
    let green_criteria = evidence.criteria.iter().filter(|seen| seen.green()).count();
    let green_now = evidence
        .red
        .iter()
        .filter(|red| red.now == Some(Outcome::Passed))
        .count();
    let in_run = |file: &str| format!("{}/{file}", evidence.folder);
    let mut said = json!({
        "card": evidence.card,
        "run": evidence.folder,
        "green": evidence.green(),
        "checks": evidence.checks.iter().map(|ran| {
            let mut said = json!({
                "name": ran.name,
                "result": said(ran.verdict),
                "exit": ran.exit_code,
                "tests": counts(ran),
                "reports": ran.reports.iter().map(|file| in_run(file)).collect::<Vec<_>>(),
                "log": ran.log.as_deref().map(in_run),
            });
            if ran.verdict != Verdict::Passed {
                let failures = ran.reported.as_ref().map(|read| &read.tested.failures[..read.tested.failures.len().min(NAMED)]);
                said["failures"] = json!(failures);
                said["last_lines"] = json!(ran.tail);
            }
            if let Some(why) = &ran.not_run {
                said["not_run"] = json!(why);
            }
            if ran.timed_out {
                said["timed_out"] = json!(true);
            }
            if !ran.media.screenshots.is_empty() || !ran.media.video.is_empty() {
                said["screenshots"] = json!(ran.media.screenshots.len());
                said["video"] = json!(ran.media.video.len());
            }
            said
        }).collect::<Vec<_>>(),
        "criteria": criteria_json(evidence),
        "criteria_green": format!("{green_criteria} of {}", evidence.criteria.len()),
        "not_mapped": evidence.not_mapped,
        "red_now_green": format!("{green_now} of {}", evidence.red.len()),
        "spec": evidence.spec.as_ref().map(|spec| json!({ "path": spec.path, "exists": spec.exists })),
        "evidence": in_run("evidence.json"),
        "attached": { "under": under, "files": attached.names.len(), "left_out": attached.left_out },
    });
    if let Some(from) = &evidence.reused_from {
        said["reused_from"] = json!(from);
    }
    if let Some(unread) = &evidence.criteria_unread {
        said["criteria_unread"] = unread_json(unread);
        said["criteria_unread"]["said"] = json!(unread_said(evidence.dialect, unread));
    }
    said
}

/// A check's tests, as a person reads them.
fn tests_said(said: &Dialect, ran: &Ran) -> String {
    if let Some(why) = &ran.not_run {
        return format!("not run: {why}");
    }
    let Some(read) = &ran.reported else {
        return match ran.exit_code {
            Some(code) => format!("exit {code}, no report {} reads", said.product),
            None => format!("no report {} reads", said.product),
        };
    };
    let tested = &read.tested;
    let mut said = vec![format!("{} passed", tested.passed)];
    if tested.failed > 0 {
        said.push(format!("{} failed", tested.failed));
    }
    if tested.skipped > 0 {
        said.push(format!("{} skipped", tested.skipped));
    }
    if ran.timed_out {
        said.push("timed out".to_owned());
    }
    said.join(", ")
}

/// The comment the run leaves on the card: one line per check, the criteria
/// and the red seen go green, and a link to each file attached, which opens
/// in devpit — pictures and videos included.
pub fn comment(evidence: &Evidence, links: &[(String, String)]) -> String {
    let green = evidence
        .checks
        .iter()
        .filter(|ran| ran.verdict == Verdict::Passed)
        .count();
    let mut text = format!(
        "{PREFIX}evidence: {green} of {} checks green, run {}\n",
        evidence.checks.len(),
        evidence.stamp
    );
    text.push('\n');
    if let Some(from) = &evidence.reused_from {
        text.push_str(&format!(
            "- not run again: the results of run {from}, at the same commit and tracked files\n"
        ));
    }
    for ran in &evidence.checks {
        text.push_str(&format!(
            "- {}: {}, {}\n",
            ran.name,
            said(ran.verdict),
            tests_said(evidence.dialect, ran)
        ));
    }
    if let Some(unread) = &evidence.criteria_unread {
        text.push_str(&format!("- {}\n", unread_said(evidence.dialect, unread)));
    }
    if !evidence.criteria.is_empty() {
        let green = evidence.criteria.iter().filter(|seen| seen.green()).count();
        text.push_str(&format!(
            "- criteria with every test green: {green} of {}\n",
            evidence.criteria.len()
        ));
    }
    if !evidence.red.is_empty() {
        let now = evidence
            .red
            .iter()
            .filter(|red| red.now == Some(Outcome::Passed))
            .count();
        text.push_str(&format!(
            "- seen red, now green: {now} of {}\n",
            evidence.red.len()
        ));
    }
    if !links.is_empty() {
        let shown: Vec<String> = links
            .iter()
            .take(LINKED)
            .map(|(name, path)| format!("[{name}]({path})"))
            .collect();
        let said = evidence.dialect;
        text.push_str(&format!("\n{}: {}", said.files_label, shown.join(" · ")));
        if links.len() > LINKED {
            text.push_str(&format!(
                " · and {} more {}",
                links.len() - LINKED,
                said.files_more
            ));
        }
        text.push('\n');
    }
    text
}

#[cfg(test)]
#[path = "evidence_tests.rs"]
mod tests;
