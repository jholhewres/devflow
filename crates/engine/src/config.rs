//! `devflow.yaml`: what a project's Devflow does. Every field but `version`
//! may be left out and takes its default; a field this version does not read
//! is an error, so a typo never passes for a setting.
//!
//! Version 2 lists the stages in order, each one `uses:` a skill — devpit's
//! own stages, and a project's or a team's beside them — and adds `extends`
//! and `locked`. Version 1's map of the six built-in stages is still read in
//! either version; a file stays version 1 until a change needs version 2,
//! which devpit then writes.

use std::cell::RefCell;
use std::collections::BTreeMap;

use serde::Serialize;

use crate::node::{self, Key, Node, Value};
use crate::scale::Scale;

/// The schema this build writes.
pub const VERSION: u64 = 2;

/// The schema whose stages are only the built-in six, as a map.
pub const V1: u64 = 1;

/// What `uses:` names devpit's own stages under.
pub const BUILTIN: &str = "builtin";

/// The stages, in the order the work goes through them.
pub const STAGES: [&str; 7] = [
    "briefing",
    "context",
    "plan",
    "execution",
    "review",
    "attack",
    "completion",
];

/// The stage that tries to exploit the change, after review: on, as
/// `sensitive`, unless devflow.yaml says otherwise.
pub const ATTACK: &str = "attack";

/// Where the E2E specs Devflow writes go, unless `stages.execution.e2e_dir` moves them.
pub const E2E_DIR: &str = ".devflow/e2e";
/// The same, in a project whose folder is devpit's.
pub const LEGACY_E2E_DIR: &str = ".devpit/devflow/e2e";

/// Where the specs go when devflow.yaml does not say: [`E2E_DIR`], or under
/// the folder a host pinned.
pub fn default_e2e_dir() -> String {
    match crate::folder::pinned() {
        Some(dir) => format!("{dir}/e2e"),
        None => E2E_DIR.to_owned(),
    }
}

/// The rubric a card's completion is gated on.
pub const GATE: &str = "devflow-done";

macro_rules! words {
    ($(#[$doc:meta])* $name:ident { $($variant:ident = $word:literal),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        pub enum $name { $($variant),+ }

        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            pub fn word(self) -> &'static str {
                match self { $($name::$variant => $word),+ }
            }

            pub(crate) fn of(word: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|one| one.word() == word)
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, to: S) -> Result<S::Ok, S::Error> {
                to.serialize_str(self.word())
            }
        }
    };
}

words!(
    /// Who approves a stage's result before anything is made of it.
    Approve { Person = "person", Nobody = "none" }
);
words!(
    /// The report a check writes, which devpit reads as its evidence.
    Report { Junit = "junit", Vitest = "vitest", Jest = "jest", Cargo = "cargo", Go = "go", Sarif = "sarif", Nothing = "none" }
);
words!(
    /// What an E2E check keeps besides its report.
    Evidence { Screenshots = "screenshots", Video = "video" }
);
words!(
    /// The agent CLIs a reviewer persona can run in.
    Agent { Claude = "claude", Codex = "codex", Cursor = "cursor", Gemini = "gemini", OpenCode = "opencode" }
);
words!(
    /// A finding's severity, as the findings schema names them.
    Severity { Critical = "critical", High = "high", Medium = "medium", Low = "low", Info = "info" }
);
words!(
    /// Where the plan's cards are made. Only the board yet.
    Publish { Board = "board", Jira = "jira", Linear = "linear", Github = "github" }
);
words!(
    /// When a planned card lets the cards waiting on it start: once it is
    /// done, or once its gate passed while it waits for the person.
    UnblockOn { Done = "done", Gate = "gate" }
);
words!(
    /// Whether Decisions only logs (`shadow`) or blocks (`enforce`).
    Mode { Shadow = "shadow", Enforce = "enforce" }
);
words!(
    /// How several reviewers' findings become one list: by Jev's
    /// `devflow-finding` rubric, by one model pass, or merged as they are.
    Consolidate { Jev = "jev", Agent = "agent", Nothing = "none" }
);
words!(
    /// Which model each stage runs on when devflow.yaml names none: `economy`
    /// runs the work and the review small and the analysis large; `quality`
    /// runs everything large.
    Models { Economy = "economy", Quality = "quality" }
);
words!(
    /// Whether the session runs the PoC of each critical and high: not
    /// asked, asked, or asked with an unconfirmed high counted as medium.
    Verify { Off = "off", Advise = "advise", Required = "required" }
);

impl Verify {
    fn off(&self) -> bool {
        *self == Verify::Off
    }
}

words!(
    /// Where the attack's exploits run: the first sandbox found here, bwrap
    /// (its own network namespace), docker (no network, the image
    /// `stages.attack.image` names), or none: the session runs them.
    SandboxChoice { Auto = "auto", Bwrap = "bwrap", Docker = "docker", Off = "off" }
);
words!(
    /// When the attack's reading runs: never, on a diff `review.scale` does
    /// not call small (past its lines, or a sensitive path), on every
    /// review, or only for a release, asked by name.
    AttackRun { Off = "off", Sensitive = "sensitive", PerItem = "per-item", Release = "release" }
);

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Config {
    pub version: u64,
    /// Written `true` only by the person's click in the app.
    pub enabled: bool,
    /// The team or company layers, each at a fixed ref.
    #[serde(skip)]
    pub extends: Vec<Extend>,
    /// The built-in stages' own settings.
    pub stages: Stages,
    /// Every stage in the order the work reaches it.
    #[serde(skip)]
    pub flow: Vec<Step>,
    pub review: Review,
    pub decisions: Decisions,
    /// The models preset; `economy` when not said.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub models: Option<Models>,
    /// The project's own running instances an attack may reach.
    #[serde(skip_serializing_if = "Security::is_empty")]
    pub security: Security,
    /// Fields a later layer may not change, by dotted path.
    #[serde(skip)]
    pub locked: Vec<String>,
}

/// A layer this one is read over: a repository at a fixed ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Extend {
    pub git: String,
    #[serde(rename = "ref")]
    pub reference: String,
}

/// What passes an own stage: a command that exits 0, or a rubric Decisions answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageGate {
    Command(String),
    Rubric(String),
}

/// One stage of the flow: a built-in one, whose settings are in [`Stages`],
/// or one of the project's or a team's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// `builtin/<stage>`, or `<where>/<name>` for an own stage.
    pub uses: String,
    /// An own stage's settings; none for a built-in one.
    pub own: Option<Own>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Own {
    pub enabled: bool,
    /// `person` makes the stage a point the work stops at for their yes.
    pub approve: Option<Approve>,
    pub gate: Option<StageGate>,
}

impl Step {
    /// The stage's name: what follows the last `/` of `uses`.
    pub fn name(&self) -> &str {
        self.uses.rsplit('/').next().unwrap_or(&self.uses)
    }

    /// The built-in stage it is, when it is one.
    pub fn builtin(&self) -> Option<&'static str> {
        let name = self.uses.strip_prefix(BUILTIN)?.strip_prefix('/')?;
        STAGES.iter().copied().find(|stage| *stage == name)
    }

    pub(crate) fn of(stage: &str) -> Step {
        Step {
            uses: format!("{BUILTIN}/{stage}"),
            own: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Stages {
    pub briefing: Approved,
    pub context: Stage,
    pub plan: Approved,
    pub execution: Execution,
    pub review: Stage,
    /// Off when its `run` is `off`.
    pub attack: Attack,
    pub completion: Completion,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Stage {
    pub enabled: bool,
    /// The model it runs on, a tier (`small`, `default`, `large`) or an id;
    /// the preset's when not said.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Approved {
    pub enabled: bool,
    pub approve: Approve,
    /// The plan's: where its cards are made. The board when not said.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publish: Option<Publish>,
    /// The plan's: when a card releases the cards waiting on it. `done` when
    /// not said.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unblock_on: Option<UnblockOn>,
    /// The model it runs on, a tier (`small`, `default`, `large`) or an id;
    /// the preset's when not said.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Execution {
    pub enabled: bool,
    pub checks: Vec<Check>,
    /// Checks run once for a release, not for each item's evidence: a long
    /// E2E suite. Read and run by name, never by the gate.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub release: Vec<Check>,
    pub e2e_dir: String,
    /// The model it runs on, a tier (`small`, `default`, `large`) or an id;
    /// the preset's when not said.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Check {
    pub name: String,
    /// One command line, run from the project's root.
    pub run: String,
    pub report: Report,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    /// A probe run first, such as `pg_isready -q`: when it fails the check is
    /// not run rather than red, since what it needs is down, not the code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires: Option<String>,
    /// A lock named per project: checks naming the same one never overlap,
    /// across cards and worktrees.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclusive: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Completion {
    pub enabled: bool,
    pub gate: String,
    /// The model it runs on, a tier (`small`, `default`, `large`) or an id;
    /// the preset's when not said.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Review {
    /// Which agent CLI runs which persona; a persona not listed is still
    /// reviewed, by the session itself.
    pub reviewers: Vec<Reviewer>,
    pub block_on: Vec<Severity>,
    pub consolidate: Consolidate,
    /// One reviewer for a small, unsensitive diff; off when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scale: Option<Scale>,
    /// `scale: false` said in the file: a re-review keeps the configured
    /// reviewers too. Absent, a re-review is read by one `devflow-all`.
    /// Written as `scale: false`, by `to_json` and `render`, when `scale`
    /// is `None`.
    #[serde(skip)]
    pub scale_off: bool,
    #[serde(skip_serializing_if = "Verify::off")]
    pub verify: Verify,
    /// One more reading before the review's, on a large model, of a diff
    /// past `scale`'s small; not said, it is on only with `models` said.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis: Option<Analysis>,
    /// `review.attack` as the file said it: the older name of
    /// `stages.attack`, which holds what is in force.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack: Option<Attack>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Analysis {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// `stages.attack` (or its older name `review.attack`): a word, or a map of
/// `run` and `model`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Attack {
    pub run: AttackRun,
    /// A tier (`small`, `default`, `large`) or an id; `large` when not said.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// The command that runs one exploit test, which it gets as
    /// `$DEVFLOW_EXPLOIT` (its path) and `$DEVFLOW_EXPLOIT_TEST` (its name):
    /// `npx jest "$DEVFLOW_EXPLOIT"`. Without it the session runs them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test: Option<String>,
    /// Where it runs: `auto` when not said.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<SandboxChoice>,
    /// The docker image a docker sandbox runs the test in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// What one run and the month's runs may spend.
    #[serde(skip_serializing_if = "Budget::is_empty")]
    pub budget: Budget,
    /// Payload classes whose cases every attack runs again.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub regression: Vec<String>,
}

/// `stages.attack.budget`: US$ per run and per calendar month, kept in
/// cents so a configuration compares exactly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Budget {
    pub run_cents: Option<u64>,
    pub month_cents: Option<u64>,
}

impl Budget {
    pub fn is_empty(&self) -> bool {
        self.run_cents.is_none() && self.month_cents.is_none()
    }

    /// Cents as the dollars a person writes.
    pub fn usd(cents: u64) -> f64 {
        cents as f64 / 100.0
    }
}

impl Serialize for Budget {
    fn serialize<S: serde::Serializer>(&self, to: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = to.serialize_map(None)?;
        if let Some(cents) = self.run_cents {
            map.serialize_entry("run_usd", &Budget::usd(cents))?;
        }
        if let Some(cents) = self.month_cents {
            map.serialize_entry("month_usd", &Budget::usd(cents))?;
        }
        map.end()
    }
}

/// The most a budget says, in dollars: a typo of zeros is refused.
const MOST_USD: f64 = 100_000.0;

/// A number of dollars, in cents.
fn dollars(field: Option<(&Node, String)>) -> Result<Option<u64>, Invalid> {
    let Some((node, path)) = field else {
        return Ok(None);
    };
    let (said, _) = scalar(node, &path, "a number of dollars")?;
    match said.parse::<f64>() {
        Ok(usd) if usd.is_finite() && usd > 0.0 && usd <= MOST_USD => {
            Ok(Some((usd * 100.0).round() as u64))
        }
        _ => Err(Invalid::at(
            node.line(),
            &path,
            &format!("a number of dollars above 0 and at most {MOST_USD}"),
        )),
    }
}

/// `budget: { run_usd, month_usd }`, dollars as numbers.
fn budget(node: &Node, path: &str) -> Result<Budget, Invalid> {
    let mut fields = Fields::of(node, path)?;
    let run_cents = dollars(fields.get("run_usd"))?;
    let month_cents = dollars(fields.get("month_usd"))?;
    fields.done()?;
    Ok(Budget {
        run_cents,
        month_cents,
    })
}

impl Default for Attack {
    /// `sensitive`: the attack runs on a diff `review.scale` does not call
    /// small.
    fn default() -> Self {
        Attack {
            run: AttackRun::Sensitive,
            model: None,
            test: None,
            sandbox: None,
            image: None,
            budget: Budget::default(),
            regression: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Reviewer {
    pub agent: Agent,
    pub persona: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// `security`: what an attack may reach. A target is in force only once the
/// person also confirmed it on a terminal (`devflow config set
/// security.targets`): a file an agent can edit is not their yes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Security {
    /// URLs of the project's own instances, each [`crate::security::target`].
    pub targets: Vec<String>,
}

impl Security {
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Decisions {
    #[serde(rename = "use")]
    pub use_: bool,
    pub mode: Mode,
    /// Stage to rubric name.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub rubrics: BTreeMap<String, String>,
}

impl Default for Config {
    fn default() -> Self {
        let approved = Approved {
            enabled: true,
            approve: Approve::Person,
            publish: None,
            unblock_on: None,
            model: None,
        };
        Config {
            version: VERSION,
            enabled: false,
            extends: Vec::new(),
            flow: STAGES.iter().map(|stage| Step::of(stage)).collect(),
            locked: Vec::new(),
            stages: Stages {
                briefing: approved.clone(),
                context: Stage {
                    enabled: true,
                    model: None,
                },
                plan: approved,
                execution: Execution {
                    enabled: true,
                    checks: Vec::new(),
                    release: Vec::new(),
                    e2e_dir: default_e2e_dir(),
                    model: None,
                },
                review: Stage {
                    enabled: true,
                    model: None,
                },
                attack: Attack::default(),
                completion: Completion {
                    enabled: true,
                    gate: GATE.to_owned(),
                    model: None,
                },
            },
            review: Review {
                reviewers: Vec::new(),
                block_on: vec![Severity::Critical, Severity::High],
                consolidate: Consolidate::Nothing,
                scale: None,
                scale_off: false,
                verify: Verify::Off,
                analysis: None,
                attack: None,
            },
            decisions: Decisions {
                use_: false,
                mode: Mode::Shadow,
                rubrics: BTreeMap::new(),
            },
            models: None,
            security: Security::default(),
        }
    }
}

impl Execution {
    /// Every check: each item's, then the release's.
    pub fn every_check(&self) -> impl Iterator<Item = &Check> {
        self.checks.iter().chain(&self.release)
    }

    /// The checks an evidence run picks from: each item's, and the
    /// release's that `named` asks for.
    pub fn runnable(&self, named: Option<&[String]>) -> Vec<Check> {
        let named = named.unwrap_or_default();
        self.checks
            .iter()
            .chain(self.release.iter().filter(|one| named.contains(&one.name)))
            .cloned()
            .collect()
    }
}

impl Stages {
    /// Whether the built-in `stage` is switched on.
    pub fn on(&self, stage: &str) -> bool {
        match stage {
            "briefing" => self.briefing.enabled,
            "context" => self.context.enabled,
            "plan" => self.plan.enabled,
            "execution" => self.execution.enabled,
            "review" => self.review.enabled,
            ATTACK => self.attack.run != AttackRun::Off,
            "completion" => self.completion.enabled,
            _ => false,
        }
    }

    pub(crate) fn switch(&mut self, stage: &str, on: bool) {
        match stage {
            "briefing" => self.briefing.enabled = on,
            "context" => self.context.enabled = on,
            "plan" => self.plan.enabled = on,
            "execution" => self.execution.enabled = on,
            "review" => self.review.enabled = on,
            ATTACK if !on => self.attack.run = AttackRun::Off,
            ATTACK if self.attack.run == AttackRun::Off => self.attack.run = AttackRun::Sensitive,
            "completion" => self.completion.enabled = on,
            _ => {}
        }
    }

    /// The `model` the built-in `stage` says, a tier or an id.
    pub fn model(&self, stage: &str) -> Option<&str> {
        match stage {
            "briefing" => self.briefing.model.as_deref(),
            "context" => self.context.model.as_deref(),
            "plan" => self.plan.model.as_deref(),
            "execution" => self.execution.model.as_deref(),
            "review" => self.review.model.as_deref(),
            ATTACK => self.attack.model.as_deref(),
            "completion" => self.completion.model.as_deref(),
            _ => None,
        }
    }

    pub(crate) fn set_model(&mut self, stage: &str, model: Option<String>) {
        match stage {
            "context" => self.context.model = model,
            "review" => self.review.model = model,
            ATTACK => self.attack.model = model,
            _ => {}
        }
    }
}

impl Config {
    /// The built-in stages switched on, in the flow's order.
    pub fn stages_on(&self) -> Vec<&'static str> {
        self.flow
            .iter()
            .filter_map(Step::builtin)
            .filter(|stage| self.stages.on(stage))
            .collect()
    }

    /// Whether a stage of the flow is switched on.
    pub fn is_on(&self, step: &Step) -> bool {
        match (step.builtin(), &step.own) {
            (Some(stage), _) => self.stages.on(stage),
            (None, Some(own)) => own.enabled,
            (None, None) => false,
        }
    }

    /// The own stages switched on, in their order.
    pub fn own_on(&self) -> Vec<&Step> {
        self.flow
            .iter()
            .filter(|step| step.builtin().is_none() && self.is_on(step))
            .collect()
    }

    /// Where the plan's cards are made: the board unless said.
    pub fn publish(&self) -> Publish {
        self.stages.plan.publish.unwrap_or(Publish::Board)
    }

    /// When a planned card releases the cards waiting on it: once done
    /// unless said.
    pub fn unblock_on(&self) -> UnblockOn {
        self.stages.plan.unblock_on.unwrap_or(UnblockOn::Done)
    }

    /// The JSON form a change is made on: version 1's map of stages, or
    /// version 2's list.
    pub fn to_json(&self) -> serde_json::Value {
        let mut json = serde_json::to_value(self).unwrap_or_default();
        // Said once, where it is in force.
        if let Some(review) = json["review"].as_object_mut() {
            review.remove(ATTACK);
        }
        if self.review.scale.is_none() && self.review.scale_off {
            json["review"]["scale"] = serde_json::Value::Bool(false);
        }
        if self.version == V1 {
            return json;
        }
        json["stages"] = serde_json::Value::Array(
            self.flow
                .iter()
                .map(|step| crate::flow::step_json(self, step))
                .collect(),
        );
        json["extends"] = serde_json::to_value(&self.extends).unwrap_or_default();
        json["locked"] = serde_json::to_value(&self.locked).unwrap_or_default();
        json
    }
}

/// Why a devflow.yaml, or a change to one, is refused: the line when there
/// is one, the field as a dotted path, and what is wrong with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Invalid {
    pub line: Option<usize>,
    pub field: String,
    pub message: String,
}

impl Invalid {
    pub(crate) fn at(line: Option<usize>, field: &str, message: &str) -> Self {
        Invalid {
            line,
            field: field.to_owned(),
            message: message.to_owned(),
        }
    }
}

impl std::fmt::Display for Invalid {
    fn fmt(&self, to: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.line, self.field.is_empty()) {
            (Some(line), false) => write!(to, "line {line}, `{}`: {}", self.field, self.message),
            (Some(line), true) => write!(to, "line {line}: {}", self.message),
            (None, false) => write!(to, "`{}`: {}", self.field, self.message),
            (None, true) => write!(to, "{}", self.message),
        }
    }
}

thread_local! {
    /// While a file is read: the fields it names that this build does not.
    static UNREAD: RefCell<Option<Vec<Invalid>>> = const { RefCell::new(None) };
}

/// The configuration a devflow.yaml text says. A field this build does not
/// read is left out, not refused: a file a newer devpit wrote still reads
/// here, and [`unread`] names what was left out.
pub fn parse(text: &str) -> Result<Config, Invalid> {
    parsed(&crate::Dialect::DEVFLOW, text).0
}

/// [`parse`], refused in `dialect`'s words.
pub fn parse_in(dialect: &crate::Dialect, text: &str) -> Result<Config, Invalid> {
    parsed(dialect, text).0
}

/// The fields `text` names that this build does not read.
pub fn unread(text: &str) -> Vec<Invalid> {
    parsed(&crate::Dialect::DEVFLOW, text).1
}

fn parsed(dialect: &crate::Dialect, text: &str) -> (Result<Config, Invalid>, Vec<Invalid>) {
    let before = UNREAD.with(|unread| unread.replace(Some(Vec::new())));
    let config = node::from_yaml(text).and_then(|root| read(dialect, &root, true));
    let unread = UNREAD.with(|unread| unread.replace(before));
    (config, unread.unwrap_or_default())
}

/// The configuration a JSON value says, checked the same way. A change made
/// through devpit that needs version 2 gets it: the version is devpit's to write.
pub fn from_json(value: &serde_json::Value) -> Result<Config, Invalid> {
    from_json_in(&crate::Dialect::DEVFLOW, value)
}

/// [`from_json`], refused in `dialect`'s words.
pub fn from_json_in(
    dialect: &crate::Dialect,
    value: &serde_json::Value,
) -> Result<Config, Invalid> {
    read(dialect, &node::from_json(value), false)
}

/// [`from_json_in`] for what the files said, layered: a field this build
/// does not read is left out, as [`parse`] leaves it, not refused.
pub(crate) fn from_files_in(
    dialect: &crate::Dialect,
    value: &serde_json::Value,
) -> Result<Config, Invalid> {
    let before = UNREAD.with(|unread| unread.replace(Some(Vec::new())));
    let config = read(dialect, &node::from_json(value), false);
    UNREAD.with(|unread| unread.replace(before));
    config
}

pub(crate) fn joined(path: &str, name: &str) -> String {
    if path.is_empty() {
        name.to_owned()
    } else {
        format!("{path}.{name}")
    }
}

/// A map being read: the fields taken so far, so whatever is left over is
/// named as the error it is.
pub(crate) struct Fields<'a> {
    path: String,
    pub(crate) line: Option<usize>,
    items: &'a [(Key, Node)],
    taken: Vec<&'static str>,
}

impl<'a> Fields<'a> {
    pub(crate) fn of(node: &'a Node, path: &str) -> Result<Self, Invalid> {
        let items: &[(Key, Node)] = match &node.value {
            Value::Map(items) => items,
            Value::Null => &[],
            _ => return Err(Invalid::at(node.line(), path, "expected a map of fields")),
        };
        Ok(Fields {
            path: path.to_owned(),
            line: node.line(),
            items,
            taken: Vec::new(),
        })
    }

    pub(crate) fn get(&mut self, name: &'static str) -> Option<(&'a Node, String)> {
        self.taken.push(name);
        self.items
            .iter()
            .find(|(key, node)| key.name == name && node.value != Value::Null)
            .map(|(_, node)| (node, joined(&self.path, name)))
    }

    /// What is left over: told and skipped in a file, refused in a change
    /// made through devpit, where the caller can still correct it.
    pub(crate) fn done(self) -> Result<(), Invalid> {
        let left = self
            .items
            .iter()
            .filter(|(key, _)| !self.taken.contains(&key.name.as_str()))
            .map(|(key, _)| {
                Invalid::at(
                    key.line,
                    &joined(&self.path, &key.name),
                    &format!(
                        "not a field of {}: it takes {}",
                        if self.path.is_empty() {
                            "devflow.yaml"
                        } else {
                            &self.path
                        },
                        self.taken.join(", ")
                    ),
                )
            });
        UNREAD.with(|unread| match unread.borrow_mut().as_mut() {
            Some(told) => {
                told.extend(left);
                Ok(())
            }
            None => left.into_iter().next().map_or(Ok(()), Err),
        })
    }
}

pub(crate) fn scalar<'a>(
    node: &'a Node,
    path: &str,
    wanted: &str,
) -> Result<(&'a str, bool), Invalid> {
    match &node.value {
        Value::Scalar(text, plain) => Ok((text, *plain)),
        _ => Err(Invalid::at(
            node.line(),
            path,
            &format!("expected {wanted}"),
        )),
    }
}

pub(crate) fn boolean(field: Option<(&Node, String)>, default: bool) -> Result<bool, Invalid> {
    let Some((node, path)) = field else {
        return Ok(default);
    };
    match scalar(node, &path, "true or false")? {
        ("true" | "True" | "TRUE", true) => Ok(true),
        ("false" | "False" | "FALSE", true) => Ok(false),
        _ => Err(Invalid::at(node.line(), &path, "expected true or false")),
    }
}

pub(crate) fn text(node: &Node, path: &str, most: usize) -> Result<String, Invalid> {
    let (text, _) = scalar(node, path, "a word or a line of text")?;
    let text = text.trim();
    if text.is_empty() || text.chars().count() > most || text.contains(['\n', '\r']) {
        return Err(Invalid::at(
            node.line(),
            path,
            &format!("expected one line of at most {most} characters"),
        ));
    }
    Ok(text.to_owned())
}

pub(crate) fn word<T: Copy>(
    node: &Node,
    path: &str,
    of: fn(&str) -> Option<T>,
    all: &[T],
    say: fn(T) -> &'static str,
) -> Result<T, Invalid> {
    let (given, _) = scalar(node, path, "a word")?;
    of(given).ok_or_else(|| {
        let words: Vec<&str> = all.iter().map(|one| say(*one)).collect();
        Invalid::at(
            node.line(),
            path,
            &format!("`{given}` is not one of {}", words.join(", ")),
        )
    })
}

pub(crate) fn items<'a>(node: &'a Node, path: &str) -> Result<&'a [Node], Invalid> {
    match &node.value {
        Value::Seq(items) => Ok(items),
        _ => Err(Invalid::at(node.line(), path, "expected a list")),
    }
}

/// A name devpit can make a file of: lowercase letters, digits, `-` and `_`.
pub fn is_name(text: &str) -> bool {
    (1..=40).contains(&text.len())
        && text
            .bytes()
            .next()
            .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_".contains(&byte))
}

pub(crate) fn name(node: &Node, path: &str) -> Result<String, Invalid> {
    let given = text(node, path, 40)?;
    if !is_name(&given) {
        return Err(Invalid::at(
            node.line(),
            path,
            "expected a name of lowercase letters, digits, - and _",
        ));
    }
    Ok(given)
}

/// A folder inside the project, written relative to its root.
pub(crate) fn inside(node: &Node, path: &str) -> Result<String, Invalid> {
    let given = text(node, path, 200)?;
    let outside = given.starts_with('/')
        || given.contains(['\\', ':'])
        || given
            .split('/')
            .any(|part| part == ".." || part.eq_ignore_ascii_case(".git"));
    if outside {
        return Err(Invalid::at(
            node.line(),
            path,
            "expected a folder inside the project, relative to its root",
        ));
    }
    Ok(given.trim_end_matches('/').to_owned())
}

fn read(dialect: &crate::Dialect, root: &Node, from_file: bool) -> Result<Config, Invalid> {
    if root.value == Value::Null {
        return Err(Invalid::at(
            None,
            "version",
            "devflow.yaml starts with `version: 2`",
        ));
    }
    let defaults = Config::default();
    let mut fields = Fields::of(root, "")?;
    let mut version = match fields.get("version") {
        Some((node, path)) => match scalar(node, &path, "1 or 2")? {
            ("1", true) => V1,
            ("2", true) => VERSION,
            (other, _) => {
                return Err(Invalid::at(
                    node.line(),
                    &path,
                    &format!(
                        "this {} reads versions 1 and 2, not {other}",
                        dialect.product
                    ),
                ))
            }
        },
        None => {
            return Err(Invalid::at(
                fields.line,
                "version",
                "devflow.yaml starts with `version: 2`",
            ))
        }
    };
    // Version 2's fields in a version 1 file: a hand edit is told; a change
    // through devpit takes version 2.
    let mut needs_two = |node: &Node, path: &str, what: &str| {
        if version == V1 {
            if from_file {
                return Err(Invalid::at(
                    node.line(),
                    path,
                    &format!("{what} is read from version 2: write `version: 2`"),
                ));
            }
            version = VERSION;
        }
        Ok(())
    };
    let enabled = boolean(fields.get("enabled"), false)?;
    let extends = match fields.get("extends") {
        Some((node, path)) => {
            needs_two(node, &path, "`extends`")?;
            crate::flow::extends(node, &path)?
        }
        None => Vec::new(),
    };
    let mut attack_said = false;
    let (stages, flow) = match fields.get("stages") {
        Some((node, path)) if matches!(node.value, Value::Seq(_)) => {
            needs_two(node, &path, "a list of stages")?;
            attack_said = names_attack(node);
            crate::flow::read(node, &path)?
        }
        Some((node, path)) => {
            attack_said = names_attack(node);
            (stages(node, &path)?, defaults.flow)
        }
        None => (defaults.stages, defaults.flow),
    };
    let locked = match fields.get("locked") {
        Some((node, path)) => {
            needs_two(node, &path, "`locked`")?;
            crate::flow::locked(node, &path)?
        }
        None => Vec::new(),
    };
    let review = match fields.get("review") {
        Some((node, path)) => review(node, &path)?,
        None => defaults.review,
    };
    let mut stages = stages;
    if let Some(said) = &review.attack {
        if attack_said && stages.attack != *said {
            return Err(Invalid::at(
                None,
                "review.attack",
                "say the attack once: stages.attack, of which review.attack is the older name",
            ));
        }
        stages.attack = said.clone();
    }
    let decisions = match fields.get("decisions") {
        Some((node, path)) => decisions(node, &path)?,
        None => defaults.decisions,
    };
    let models = match fields.get("models") {
        Some((node, path)) => Some(word(node, &path, Models::of, Models::ALL, Models::word)?),
        None => None,
    };
    let security = match fields.get("security") {
        Some((node, path)) => security(node, &path)?,
        None => Security::default(),
    };
    fields.done()?;
    Ok(Config {
        version,
        enabled,
        extends,
        stages,
        flow,
        review,
        decisions,
        models,
        security,
        locked,
    })
}

/// `security.targets`: each a target [`crate::security::target`] reads, at
/// most [`crate::security::MOST_TARGETS`], refused with its line.
fn security(node: &Node, path: &str) -> Result<Security, Invalid> {
    let mut fields = Fields::of(node, path)?;
    let mut targets: Vec<String> = Vec::new();
    if let Some((node, path)) = fields.get("targets") {
        let listed = items(node, &path)?;
        if listed.len() > crate::security::MOST_TARGETS {
            return Err(Invalid::at(
                node.line(),
                &path,
                &format!("at most {} targets", crate::security::MOST_TARGETS),
            ));
        }
        for (index, item) in listed.iter().enumerate() {
            let at = format!("{path}.{index}");
            let url = text(item, &at, crate::security::LONGEST)?;
            crate::security::target(&url).map_err(|why| Invalid::at(item.line(), &at, &why))?;
            if !targets.contains(&url) {
                targets.push(url);
            }
        }
    }
    fields.done()?;
    Ok(Security { targets })
}

fn stage(field: Option<(&Node, String)>) -> Result<Stage, Invalid> {
    let Some((node, path)) = field else {
        return Ok(Stage {
            enabled: true,
            model: None,
        });
    };
    let mut fields = Fields::of(node, &path)?;
    let enabled = boolean(fields.get("enabled"), true)?;
    let model = model(fields.get("model"))?;
    fields.done()?;
    Ok(Stage { enabled, model })
}

/// The tiers a `model` may name; anything else is a model id.
pub const TIERS: [&str; 3] = ["small", "default", "large"];
/// The longest model id read.
const LONGEST_MODEL: usize = 100;

/// A model as written, held to what one is: a tier, exactly, or a model id
/// of letters, digits and `. _ : / @ [ ] -` that starts with a letter or a
/// digit, so it can never be read as a flag of the CLI it is passed to.
pub fn model_said(text: &str) -> Result<&str, String> {
    let said = text.trim();
    if TIERS.contains(&said) {
        return Ok(said);
    }
    if let Some(tier) = TIERS.iter().find(|tier| tier.eq_ignore_ascii_case(said)) {
        return Err(format!("`{said}` is not a tier: write it `{tier}`"));
    }
    let id = said.len() <= LONGEST_MODEL
        && said
            .bytes()
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric())
        && said
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/@[]-".contains(&byte));
    if id {
        Ok(said)
    } else {
        let (last, rest) = TIERS.split_last().unwrap_or((&"", &[]));
        Err(format!(
            "`{said}` is not a model: a tier ({} or {last}) or a model id such as \
             claude-opus-5-5, of letters, digits and . _ : / @ [ ] -, starting with a letter or a digit",
            rest.join(", ")
        ))
    }
}

/// A stage's `model`: a tier or a model id, as [`model_said`] holds it.
pub(crate) fn model(field: Option<(&Node, String)>) -> Result<Option<String>, Invalid> {
    match field {
        Some((node, path)) => {
            let said = text(node, &path, LONGEST_MODEL)?;
            model_said(&said)
                .map(|said| Some(said.to_owned()))
                .map_err(|why| Invalid::at(node.line(), &path, &why))
        }
        None => Ok(None),
    }
}

/// An approved stage's own fields; `publish` only where `plan` says it.
pub(crate) fn approved_in(fields: &mut Fields, plan: bool) -> Result<Approved, Invalid> {
    let enabled = boolean(fields.get("enabled"), true)?;
    let approve = match fields.get("approve") {
        Some((node, path)) => word(node, &path, Approve::of, Approve::ALL, Approve::word)?,
        None => Approve::Person,
    };
    let publish = match plan.then(|| fields.get("publish")).flatten() {
        Some((node, path)) => Some(word(node, &path, Publish::of, Publish::ALL, Publish::word)?),
        None => None,
    };
    let unblock_on = match plan.then(|| fields.get("unblock_on")).flatten() {
        Some((node, path)) => Some(word(
            node,
            &path,
            UnblockOn::of,
            UnblockOn::ALL,
            UnblockOn::word,
        )?),
        None => None,
    };
    let model = model(fields.get("model"))?;
    Ok(Approved {
        enabled,
        approve,
        publish,
        unblock_on,
        model,
    })
}

fn approved(field: Option<(&Node, String)>, plan: bool) -> Result<Approved, Invalid> {
    let Some((node, path)) = field else {
        return Ok(Config::default().stages.plan);
    };
    let mut fields = Fields::of(node, &path)?;
    let approved = approved_in(&mut fields, plan)?;
    fields.done()?;
    Ok(approved)
}

fn stages(node: &Node, path: &str) -> Result<Stages, Invalid> {
    let mut fields = Fields::of(node, path)?;
    let briefing = approved(fields.get("briefing"), false)?;
    let context = stage(fields.get("context"))?;
    let plan = approved(fields.get("plan"), true)?;
    let execution = match fields.get("execution") {
        Some((node, path)) => {
            let mut fields = Fields::of(node, &path)?;
            let execution = execution_in(&mut fields)?;
            fields.done()?;
            execution
        }
        None => Config::default().stages.execution,
    };
    let review = stage(fields.get("review"))?;
    let attack = match fields.get(ATTACK) {
        Some((node, path)) if matches!(node.value, Value::Scalar(..)) => attack(node, &path)?,
        Some((node, path)) => {
            let mut fields = Fields::of(node, &path)?;
            let attack = attack_in(&mut fields)?;
            fields.done()?;
            attack
        }
        None => Attack::default(),
    };
    let completion = match fields.get("completion") {
        Some((node, path)) => {
            let mut fields = Fields::of(node, &path)?;
            let enabled = boolean(fields.get("enabled"), true)?;
            let gate = match fields.get("gate") {
                Some((node, path)) => name(node, &path)?,
                None => GATE.to_owned(),
            };
            let model = model(fields.get("model"))?;
            fields.done()?;
            Completion {
                enabled,
                gate,
                model,
            }
        }
        None => Config::default().stages.completion,
    };
    fields.done()?;
    Ok(Stages {
        briefing,
        context,
        plan,
        execution,
        review,
        attack,
        completion,
    })
}

/// The execution stage's own fields.
pub(crate) fn execution_in(fields: &mut Fields) -> Result<Execution, Invalid> {
    let enabled = boolean(fields.get("enabled"), true)?;
    let mut checks: Vec<Check> = Vec::new();
    let mut release: Vec<Check> = Vec::new();
    // One name per check, across both lists: a check's script is its name.
    for key in ["checks", "release"] {
        let Some((node, path)) = fields.get(key) else {
            continue;
        };
        for (index, item) in items(node, &path)?.iter().enumerate() {
            let at = format!("{path}.{index}");
            let made = check(item, &at)?;
            if checks
                .iter()
                .chain(&release)
                .any(|one| one.name == made.name)
            {
                return Err(Invalid::at(
                    item.line(),
                    &format!("{at}.name"),
                    &format!("a check called `{}` is already listed", made.name),
                ));
            }
            if key == "checks" {
                checks.push(made);
            } else {
                release.push(made);
            }
        }
    }
    let e2e_dir = match fields.get("e2e_dir") {
        Some((node, path)) => inside(node, &path)?,
        None => default_e2e_dir(),
    };
    let model = model(fields.get("model"))?;
    Ok(Execution {
        enabled,
        checks,
        release,
        e2e_dir,
        model,
    })
}

pub(crate) fn check(node: &Node, path: &str) -> Result<Check, Invalid> {
    let mut fields = Fields::of(node, path)?;
    let line = fields.line;
    let name = match fields.get("name") {
        Some((node, path)) => name(node, &path)?,
        None => {
            return Err(Invalid::at(
                line,
                &joined(path, "name"),
                "a check needs a name",
            ))
        }
    };
    let run = match fields.get("run") {
        Some((node, path)) => text(node, &path, 1000)?,
        None => {
            return Err(Invalid::at(
                line,
                &joined(path, "run"),
                "a check needs a command to run",
            ))
        }
    };
    let report = match fields.get("report") {
        Some((node, path)) => word(node, &path, Report::of, Report::ALL, Report::word)?,
        None => Report::Nothing,
    };
    let mut evidence = Vec::new();
    if let Some((node, path)) = fields.get("evidence") {
        for (index, item) in items(node, &path)?.iter().enumerate() {
            let kept = word(
                item,
                &format!("{path}.{index}"),
                Evidence::of,
                Evidence::ALL,
                Evidence::word,
            )?;
            if !evidence.contains(&kept) {
                evidence.push(kept);
            }
        }
    }
    let requires = match fields.get("requires") {
        Some((node, path)) => Some(text(node, &path, 1000)?),
        None => None,
    };
    let exclusive = match fields.get("exclusive") {
        Some((node, path)) => Some(self::name(node, &path)?),
        None => None,
    };
    fields.done()?;
    Ok(Check {
        name,
        run,
        report,
        evidence,
        requires,
        exclusive,
    })
}

pub(crate) fn review(node: &Node, path: &str) -> Result<Review, Invalid> {
    let mut fields = Fields::of(node, path)?;
    let mut reviewers = Vec::new();
    if let Some((node, path)) = fields.get("reviewers") {
        for (index, item) in items(node, &path)?.iter().enumerate() {
            reviewers.push(reviewer(item, &format!("{path}.{index}"))?);
        }
    }
    let block_on = match fields.get("block_on") {
        Some((node, path)) => {
            let mut severities = Vec::new();
            for (index, item) in items(node, &path)?.iter().enumerate() {
                let severity = word(
                    item,
                    &format!("{path}.{index}"),
                    Severity::of,
                    Severity::ALL,
                    Severity::word,
                )?;
                if !severities.contains(&severity) {
                    severities.push(severity);
                }
            }
            severities
        }
        None => Config::default().review.block_on,
    };
    let consolidate = match fields.get("consolidate") {
        Some((node, path)) => word(
            node,
            &path,
            Consolidate::of,
            Consolidate::ALL,
            Consolidate::word,
        )?,
        None => Config::default().review.consolidate,
    };
    let (scale, scale_off) = match fields.get("scale") {
        Some((node, path)) => {
            let scale = scale(node, &path)?;
            let off = scale.is_none();
            (scale, off)
        }
        None => (None, false),
    };
    let verify = match fields.get("verify") {
        Some((node, path)) => word(node, &path, Verify::of, Verify::ALL, Verify::word)?,
        None => Verify::Off,
    };
    let analysis = match fields.get("analysis") {
        Some((node, path)) => Some(analysis(node, &path)?),
        None => None,
    };
    let attack = match fields.get("attack") {
        Some((node, path)) => Some(attack(node, &path)?),
        None => None,
    };
    fields.done()?;
    Ok(Review {
        reviewers,
        block_on,
        consolidate,
        scale,
        scale_off,
        verify,
        analysis,
        attack,
    })
}

/// `attack: off|sensitive|per-item|release`, or a map of `run` and `model`.
fn attack(node: &Node, path: &str) -> Result<Attack, Invalid> {
    let run =
        |node: &Node, path: &str| word(node, path, AttackRun::of, AttackRun::ALL, AttackRun::word);
    if matches!(node.value, Value::Scalar(..)) {
        return Ok(Attack {
            run: run(node, path)?,
            ..Attack::default()
        });
    }
    let mut fields = Fields::of(node, path)?;
    let line = fields.line;
    let said = match fields.get("run") {
        Some((node, path)) => run(node, &path)?,
        None => {
            return Err(Invalid::at(
                line,
                &joined(path, "run"),
                "say when the attack runs: off, sensitive, per-item or release",
            ))
        }
    };
    let mut attack = attack_in(&mut fields)?;
    attack.run = said;
    fields.done()?;
    Ok(attack)
}

/// Whether `stages` names the attack: a map's `attack`, or a list's
/// `uses: builtin/attack`.
fn names_attack(stages: &Node) -> bool {
    let builtin = format!("{BUILTIN}/{ATTACK}");
    match &stages.value {
        Value::Map(fields) => fields.iter().any(|(key, _)| key.name == ATTACK),
        Value::Seq(items) => items.iter().any(|item| match &item.value {
            Value::Map(fields) => fields.iter().any(|(key, uses)| {
                key.name == "uses"
                    && matches!(&uses.value, Value::Scalar(said, _) if *said == builtin)
            }),
            _ => false,
        }),
        _ => false,
    }
}

/// The attack stage's own fields: `enabled` (`false` is `run: off`), `run`
/// (`sensitive` when not said) and `model`.
pub(crate) fn attack_in(fields: &mut Fields) -> Result<Attack, Invalid> {
    let enabled = boolean(fields.get("enabled"), true)?;
    let run = match fields.get("run") {
        Some((node, path)) => word(node, &path, AttackRun::of, AttackRun::ALL, AttackRun::word)?,
        None => Attack::default().run,
    };
    let model = model(fields.get("model"))?;
    let test = match fields.get("test") {
        Some((node, path)) => Some(text(node, &path, 500)?),
        None => None,
    };
    let sandbox = match fields.get("sandbox") {
        Some((node, path)) => Some(word(
            node,
            &path,
            SandboxChoice::of,
            SandboxChoice::ALL,
            SandboxChoice::word,
        )?),
        None => None,
    };
    let image = match fields.get("image") {
        Some((node, path)) => Some(text(node, &path, 200)?),
        None => None,
    };
    let budget = match fields.get("budget") {
        Some((node, path)) => budget(node, &path)?,
        None => Budget::default(),
    };
    let mut regression: Vec<String> = Vec::new();
    if let Some((node, path)) = fields.get("regression") {
        for (index, item) in items(node, &path)?.iter().enumerate() {
            let at = format!("{path}.{index}");
            let class = text(item, &at, 40)?;
            crate::payloads::shipped(&class).map_err(|why| Invalid::at(item.line(), &at, &why))?;
            if !regression.contains(&class) {
                regression.push(class);
            }
        }
    }
    Ok(Attack {
        run: if enabled { run } else { AttackRun::Off },
        model,
        test,
        sandbox,
        image,
        budget,
        regression,
    })
}

/// `analysis: true` or `false`, or a map of `enabled` and `model`.
fn analysis(node: &Node, path: &str) -> Result<Analysis, Invalid> {
    if matches!(node.value, Value::Scalar(..)) {
        let enabled = boolean(Some((node, path.to_owned())), false)?;
        return Ok(Analysis {
            enabled,
            model: None,
        });
    }
    let mut fields = Fields::of(node, path)?;
    let enabled = boolean(fields.get("enabled"), true)?;
    let model = model(fields.get("model"))?;
    fields.done()?;
    Ok(Analysis { enabled, model })
}

/// `scale: true` for the defaults, `false` for off, or a map of either field.
fn scale(node: &Node, path: &str) -> Result<Option<Scale>, Invalid> {
    if matches!(node.value, Value::Scalar(..)) {
        let on = boolean(Some((node, path.to_owned())), false)?;
        return Ok(on.then(Scale::default));
    }
    let mut fields = Fields::of(node, path)?;
    let mut scale = Scale::default();
    if let Some((node, path)) = fields.get("small_lines") {
        scale.small_lines = match scalar(node, &path, "a number of lines")? {
            (given, true) => given.parse().ok().filter(|lines| *lines > 0),
            _ => None,
        }
        .ok_or_else(|| Invalid::at(node.line(), &path, "expected a number of lines above 0"))?;
    }
    if let Some((node, path)) = fields.get("sensitive") {
        scale.sensitive = items(node, &path)?
            .iter()
            .enumerate()
            .map(|(index, item)| text(item, &format!("{path}.{index}"), 200))
            .collect::<Result<_, _>>()?;
    }
    fields.done()?;
    Ok(Some(scale))
}

fn reviewer(node: &Node, path: &str) -> Result<Reviewer, Invalid> {
    let mut fields = Fields::of(node, path)?;
    let line = fields.line;
    let agent = match fields.get("agent") {
        Some((node, path)) => word(node, &path, Agent::of, Agent::ALL, Agent::word)?,
        None => {
            return Err(Invalid::at(
                line,
                &joined(path, "agent"),
                "a reviewer needs an agent",
            ))
        }
    };
    let persona = match fields.get("persona") {
        Some((node, path)) => name(node, &path)?,
        None => {
            return Err(Invalid::at(
                line,
                &joined(path, "persona"),
                "a reviewer needs a persona",
            ))
        }
    };
    let model = model(fields.get("model"))?;
    fields.done()?;
    Ok(Reviewer {
        agent,
        persona,
        model,
    })
}

fn decisions(node: &Node, path: &str) -> Result<Decisions, Invalid> {
    let mut fields = Fields::of(node, path)?;
    let use_ = boolean(fields.get("use"), false)?;
    let mode = match fields.get("mode") {
        Some((node, path)) => word(node, &path, Mode::of, Mode::ALL, Mode::word)?,
        None => Mode::Shadow,
    };
    let mut rubrics = BTreeMap::new();
    if let Some((node, path)) = fields.get("rubrics") {
        let Value::Map(items) = &node.value else {
            return Err(Invalid::at(
                node.line(),
                &path,
                "expected a map of stage to rubric",
            ));
        };
        for (key, rubric) in items {
            let at = joined(&path, &key.name);
            if !STAGES.contains(&key.name.as_str()) {
                return Err(Invalid::at(
                    key.line,
                    &at,
                    &format!("not a stage: the stages are {}", STAGES.join(", ")),
                ));
            }
            rubrics.insert(key.name.clone(), name(rubric, &at)?);
        }
    }
    fields.done()?;
    Ok(Decisions {
        use_,
        mode,
        rubrics,
    })
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
