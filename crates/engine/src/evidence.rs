//! `devpit_devflow_evidence`: a card's checks run through devpit's steps
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
use crate::plan::PREFIX;
use crate::runs::{self, Attached, Media, Runs};

/// The fields the tool takes, as the execution and completion skills send
/// them; `project` is an orchestrator's, as on every board tool.
pub const FIELDS: [&str; 4] = ["card", "checks", "criteria", "red"];

const SHAPE: &str =
    "{ card, checks?: [name], criteria?: [{ criterion, tests?: [test id], proof?: { kind: screenshot|e2e|artifact, path } }], red?: [{ test, failure }] }";
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
}

/// The tool's input, refused with the shape it takes when it is not that.
pub fn asked(params: &Value) -> Result<Asked, String> {
    let extra = params.as_object().and_then(|fields| {
        fields
            .keys()
            .find(|key| !FIELDS.contains(&key.as_str()) && key.as_str() != "project")
    });
    if let Some(extra) = extra {
        return Err(format!(
            "`{extra}` is not a field of the evidence: it takes {SHAPE}"
        ));
    }
    let asked: Asked = serde_json::from_value(params.clone())
        .map_err(|why| format!("the evidence is {SHAPE}: {why}"))?;
    if asked.card.trim().is_empty() {
        return Err("which card? pass its id as `card`".to_owned());
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
    if checks.is_empty() {
        return Err(
            "devflow.yaml configures no checks under stages.execution.checks: devpit_devflow_set adds one"
                .to_owned(),
        );
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
    let checks = chosen(&config.stages.execution.checks, asked.checks.as_deref())?;
    let run = kept.fresh(card.id, *at)?;
    let folder = run.display().to_string();
    let started = Instant::now();
    let ran: Vec<Ran> = checks
        .iter()
        .map(|check| {
            let left = budget.saturating_sub(started.elapsed());
            if left < Duration::from_secs(1) {
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
    };
    let record = serde_json::to_string_pretty(&recorded(&evidence)).unwrap_or_default();
    std::fs::write(run.join("evidence.json"), record).map_err(|err| err.to_string())?;
    if let Some(parent) = run.parent() {
        evidence.pruned = runs::prune(parent, runs::KEPT);
    }
    Ok(evidence)
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
    json!({
        "devpit": crate::skills::made_by(&["devflow-execution", "devflow-completion"]),
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
    json!({
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
    })
}

/// A check's tests, as a person reads them.
fn tests_said(ran: &Ran) -> String {
    if let Some(why) = &ran.not_run {
        return format!("not run: {why}");
    }
    let Some(read) = &ran.reported else {
        return match ran.exit_code {
            Some(code) => format!("exit {code}, no report devpit reads"),
            None => "no report devpit reads".to_owned(),
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
    for ran in &evidence.checks {
        text.push_str(&format!(
            "- {}: {}, {}\n",
            ran.name,
            said(ran.verdict),
            tests_said(ran)
        ));
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
        text.push_str(&format!("\nAttached: {}", shown.join(" · ")));
        if links.len() > LINKED {
            text.push_str(&format!(
                " · and {} more among the artifacts",
                links.len() - LINKED
            ));
        }
        text.push('\n');
    }
    text
}

#[cfg(test)]
#[path = "evidence_tests.rs"]
mod tests;
