//! What an attack needs that only the person gives: devflow switched on in
//! the project, the attack stage on, the command that runs one exploit test,
//! the sandbox, a budget, and the targets it may reach. Asked as one
//! question: through the client (MCP's `elicitation/create`), or, where the
//! client cannot ask, by one command on a terminal. Either way the answer is
//! applied here: devflow.yaml edited in place, keeping what devpit or the
//! person wrote, and each yes kept in consent.json with how it came.

use std::ffi::OsStr;
use std::time::SystemTime;

use devflow_engine::config::{Config, SandboxChoice};
use devflow_engine::detect::{self, ExploitTest};
use devflow_engine::folder::State;
use devflow_engine::preset::Preset;
use devflow_engine::security::Pins;
use devflow_engine::{proposal, sandbox, setup, Ask};
use serde_json::{json, Map, Value};
use sha2::Digest;

use crate::consent::{Consent, How};
use crate::person::Answer;
use crate::project::Project;
use crate::server::Server;

/// The one command that does it all on a terminal, for a client that cannot
/// ask the person.
pub const COMMAND: &str = "devflow setup --attack";
/// What the budget starts at when the person is asked: US$ per attack, and
/// per calendar month.
pub const RUN_USD: f64 = 5.0;
pub const MONTH_USD: f64 = 50.0;
/// The most a budget says, in dollars, as devflow.yaml reads it.
const MOST_USD: f64 = 100_000.0;
/// What the attack was asked for, as consent.json keeps it.
const FOR: &str = "attack";

/// What the attack needs from the person in a project.
#[derive(Debug, Clone, PartialEq)]
pub struct Wanted {
    /// There is no devflow.yaml: the recommended setup is written.
    pub setup: bool,
    /// devflow is off here: the file's `enabled`, devflow's switch on this
    /// machine, or both.
    pub switch: bool,
    /// The file says `enabled: false`, which the switch sets too.
    pub file_off: bool,
    /// The attack stage is off: it is set to run when asked by name.
    pub stage: bool,
    /// `stages.attack.test` is not set: the command detected, if any.
    pub test: Option<Option<ExploitTest>>,
    /// `stages.attack.sandbox` is not set: what `auto` finds here.
    pub sandbox: Option<String>,
    /// `stages.attack.image` is not set and docker is here: the image
    /// suggested for the project's runner.
    pub image: Option<String>,
    pub run_usd: bool,
    pub month_usd: bool,
    /// The targets devflow.yaml lists that the person has not confirmed and
    /// that a yes could put in force, each shown with what it resolves to.
    pub targets: Vec<String>,
    /// Every target listed, and what each name resolves to now: what is
    /// shown is what is kept.
    pub listed: Vec<String>,
    pub found: Pins,
    /// The targets asked, named by what they are and resolve to: the same
    /// ones are not asked again once answered.
    pub targets_part: String,
}

impl Wanted {
    /// Without these the attack does not run.
    pub fn needed(&self) -> bool {
        self.setup || self.switch || self.stage
    }

    /// The attack runs without these, but runs better with them.
    pub fn optional(&self) -> bool {
        self.test.is_some()
            || self.sandbox.is_some()
            || self.image.is_some()
            || self.run_usd
            || self.month_usd
            || !self.targets.is_empty()
    }

    /// What is missing, in a few words.
    pub fn summary(&self) -> String {
        let mut said: Vec<&str> = Vec::new();
        if self.setup {
            said.push("there is no devflow.yaml here");
        } else if self.switch {
            said.push("devflow is not on in this project");
        }
        if self.stage {
            said.push("the attack stage is off");
        }
        if self.test.is_some() {
            said.push("stages.attack.test is not set");
        }
        if self.run_usd || self.month_usd {
            said.push("the attack has no budget");
        }
        if !self.targets.is_empty() {
            said.push("security.targets wait for the person's yes");
        }
        if said.is_empty() {
            said.push("the attack's setup is not finished");
        }
        said.join(", ")
    }

    /// The parts of the question the attack runs without, by name: once
    /// answered, yes or no, they are not asked again through the client.
    pub fn parts(&self) -> Vec<String> {
        let mut parts: Vec<String> = [
            ("test", self.test.is_some()),
            ("sandbox", self.sandbox.is_some()),
            ("image", self.image.is_some()),
            ("run_usd", self.run_usd),
            ("month_usd", self.month_usd),
        ]
        .into_iter()
        .filter(|(_, asked)| *asked)
        .map(|(name, _)| name.to_owned())
        .collect();
        if !self.targets.is_empty() {
            parts.push(self.targets_part.clone());
        }
        parts
    }

    /// The question, said once: its message and its form.
    pub fn question(&self, project: &Project) -> (String, Value) {
        let mut said = vec![format!(
            "devflow's attack on {} needs your answer.",
            project.root.display()
        )];
        if self.setup {
            said.push(format!(
                "There is no devflow.yaml here: accepting writes the recommended setup in {}/, \
                 yours to commit.",
                project.dir()
            ));
        }
        if self.switch {
            said.push(
                "devflow is off in this project on this machine: accepting switches it on."
                    .to_owned(),
            );
        }
        if self.stage {
            said.push(
                "The attack stage is off: accepting sets it to run when asked by name \
                 (run: release)."
                    .to_owned(),
            );
        }
        if self.optional() {
            said.push(
                "The fields go into devflow.yaml's stages.attack; one left empty stays unset."
                    .to_owned(),
            );
        }
        said.push("Nothing is committed. Declining leaves everything as it is.".to_owned());
        let mut fields = Map::new();
        if self.needed() {
            fields.insert(
                "switch_on".to_owned(),
                json!({ "type": "boolean", "title": "Switch devflow on here", "default": true,
                    "description": "devflow's switch for this project, kept on this machine." }),
            );
        }
        if let Some(found) = &self.test {
            let mut field = json!({ "type": "string", "title": "Exploit test command", "maxLength": 500,
                "description": "Runs one exploit test, given its path as $DEVFLOW_EXPLOIT and its name as $DEVFLOW_EXPLOIT_TEST. Empty: the session runs each exploit." });
            if let Some(found) = found {
                field["default"] = json!(found.command);
                field["description"] = json!(format!(
                    "Runs one exploit test, given its path as $DEVFLOW_EXPLOIT and its name as \
                     $DEVFLOW_EXPLOIT_TEST. Found from {}. Empty: the session runs each exploit.",
                    found.source
                ));
            }
            fields.insert("test".to_owned(), field);
        }
        if let Some(here) = &self.sandbox {
            fields.insert(
                "sandbox".to_owned(),
                json!({ "type": "string", "title": "Sandbox", "enum": SandboxChoice::ALL.iter().map(|one| one.word()).collect::<Vec<_>>(),
                    "default": SandboxChoice::Auto.word(),
                    "description": format!("Where each exploit runs, with no network: auto finds {here} here; bwrap (a network namespace of its own), docker (the image below), off (the session runs them).") }),
            );
        }
        if let Some(image) = &self.image {
            let mut field = json!({ "type": "string", "title": "Docker image", "maxLength": 200,
                "description": "The image a docker sandbox runs the exploit test in." });
            if !image.is_empty() {
                field["default"] = json!(image);
            }
            fields.insert("image".to_owned(), field);
        }
        for (wanted, name, title, default) in [
            (self.run_usd, "run_usd", "Budget per attack, US$", RUN_USD),
            (
                self.month_usd,
                "month_usd",
                "Budget per month, US$",
                MONTH_USD,
            ),
        ] {
            if wanted {
                fields.insert(
                    name.to_owned(),
                    json!({ "type": "number", "title": title, "minimum": 0.01, "maximum": MOST_USD, "default": default }),
                );
            }
        }
        if !self.targets.is_empty() {
            let shown: Vec<String> = self
                .targets
                .iter()
                .map(|url| crate::cli::shown(url, &self.found))
                .collect();
            fields.insert(
                "targets".to_owned(),
                json!({ "type": "boolean", "title": "Allow these targets", "default": false,
                    "description": format!("The attack may send requests, exploits included, to: {}. They must be this project's own instances, never a third party's.", shown.join("; ")) }),
            );
        }
        let schema = json!({ "type": "object", "properties": fields });
        (said.join(" "), schema)
    }
}

/// What the attack needs from the person in `project`, with what this
/// machine has on `path`. A part the person answered before is left out,
/// unless asked `again` (their own command on a terminal).
pub fn wanted(
    project: &Project,
    consent: &Consent,
    path: &OsStr,
    again: bool,
) -> Result<Wanted, String> {
    let root = project.root.as_path();
    let detected = detect::detected(root, crate::flow::setup::machine(root));
    let state = project.read();
    let (setup, config) = match &state {
        State::Missing => (
            true,
            devflow_engine::preset::starting(Preset::Recommended, &detected),
        ),
        State::Valid(_, config) => (false, (**config).clone()),
        State::Invalid(_, invalid) => {
            return Err(format!(
                "devflow.yaml is invalid ({invalid}): `set` fixes the field it names, and then \
                 the attack asks the person"
            ))
        }
    };
    let attack = &config.stages.attack;
    let exploit = detect::exploit_test(&detected);
    let docker = devflow_engine::env::found_on(path, OsStr::new("docker")).is_some();
    let suggested = exploit.as_ref().map(|found| found.image);
    let here = match sandbox::found(SandboxChoice::Auto, suggested, path) {
        Ok(found) => found.kind.word(),
        Err(_) => "nothing",
    };
    let (targets, found) = to_confirm(project, consent, &config);
    let shown: Vec<String> = targets
        .iter()
        .map(|url| crate::cli::shown(url, &found))
        .collect();
    let digest = sha2::Sha256::digest(shown.join("\n").as_bytes());
    let targets_part = format!("targets:sha256:{digest:x}");
    let answered = if again {
        Default::default()
    } else {
        consent.answered(root)
    };
    let open = |part: &str| !answered.contains(part);
    Ok(Wanted {
        setup,
        switch: setup || !config.enabled || !consent.made(root, Ask::Enable),
        file_off: !setup && !config.enabled,
        stage: !config.stages_on().contains(&"attack"),
        test: (attack.test.is_none() && open("test")).then_some(exploit),
        sandbox: (attack.sandbox.is_none() && open("sandbox")).then(|| here.to_owned()),
        image: (attack.image.is_none() && docker && open("image"))
            .then(|| suggested.unwrap_or_default().to_owned()),
        run_usd: attack.budget.run_cents.is_none() && open("run_usd"),
        month_usd: attack.budget.month_cents.is_none() && open("month_usd"),
        targets: if open(&targets_part) {
            targets
        } else {
            Vec::new()
        },
        listed: config.security.targets.clone(),
        found,
        targets_part,
    })
}

/// Before an attack: what it needs from the person here, asked as one
/// question through the client, and applied on their yes. What the answer
/// set, or a note for the person, goes in the attack's answer; their no, or a
/// client that cannot ask when devflow is off, stops the attack and says
/// why. `launching`: a new attack, which also asks what it runs without; a
/// call on a run already made asks only what it cannot run without.
pub fn before_attack(
    server: &Server,
    project: &Project,
    launching: bool,
) -> Result<Option<Value>, String> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let wanted = wanted(project, &server.consent, &path, false)?;
    let asks = wanted.needed() || (launching && wanted.optional());
    if !asks {
        return Ok(None);
    }
    let stopped = "nothing was written, and the attack did not run";
    if let Some(since) = server.person.no_stands() {
        if !wanted.needed() {
            return Ok(None);
        }
        return Err(format!(
            "The person said no to devflow's question {} ago ({}): {stopped}. It is not asked \
             again in this session for {} minutes; the person can run `{COMMAND}` in a \
             terminal.",
            minutes(since),
            wanted.summary(),
            crate::person::NO_STANDS.as_secs() / 60
        ));
    }
    let (message, schema) = wanted.question(project);
    let answer = server.ask(&message, schema);
    if matches!(answer, Answer::Declined | Answer::Cancelled) {
        server.person.heard_no();
    }
    match answer {
        Answer::Accepted(content) => apply(
            project,
            &server.consent,
            &wanted,
            &content,
            How::Elicitation,
            SystemTime::now(),
        )
        .map(|applied| Some(applied.to_json()))
        .map_err(|not| {
            server.person.heard_no();
            match not {
                NotApplied::Unread(why) => {
                    format!("The person's answer was not applied ({why}): {stopped}.")
                }
                NotApplied::Partly(why) => {
                    format!("The person's answer was applied only in part ({why}): the attack did not run.")
                }
            }
        }),
        Answer::Declined => Err(format!(
            "The person declined devflow's question ({}): {stopped}.",
            wanted.summary()
        )),
        Answer::Cancelled => Err(format!(
            "The person did not answer devflow's question ({}): {stopped}.",
            wanted.summary()
        )),
        Answer::Unasked(why) if wanted.needed() => Err(format!(
            "{}, and {why}. The person runs `{COMMAND}` in a terminal, once: it shows the same \
             choices, each detected from the project, asks for one yes, and the attack runs \
             after. No tool does it for them.",
            capitalized(&wanted.summary())
        )),
        Answer::Unasked(_) => Ok(Some(json!({
            "for_the_person": format!(
                "{}: the attack runs without it. The person runs `{COMMAND}` in a terminal to \
                 set it.",
                capitalized(&wanted.summary())
            ),
        }))),
    }
}

/// A span as a person says it.
fn minutes(span: std::time::Duration) -> String {
    match span.as_secs() / 60 {
        0 => "less than a minute".to_owned(),
        1 => "a minute".to_owned(),
        many => format!("{many} minutes"),
    }
}

fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// The targets listed that the person has not confirmed, or whose names
/// resolve elsewhere now, each one a yes could put in force; and what every
/// listed name resolves to now.
fn to_confirm(project: &Project, consent: &Consent, config: &Config) -> (Vec<String>, Pins) {
    let listed = &config.security.targets;
    if listed.is_empty() {
        return (Vec::new(), Pins::new());
    }
    let found =
        devflow_engine::security::resolved(listed, &devflow_engine::security::resolved_here_all);
    let asked = crate::cli::to_confirm(
        listed,
        &consent.confirmed_targets(&project.root),
        &consent.pinned(&project.root),
        &found,
    )
    .into_iter()
    .filter(|url| devflow_engine::security::pinnable(url, &found).is_ok())
    .collect();
    (asked, found)
}

/// The answer as devflow reads it: only the fields that were asked.
#[derive(Debug, Default)]
struct Read {
    switch_on: bool,
    test: Option<String>,
    sandbox: Option<SandboxChoice>,
    image: Option<String>,
    run_usd: Option<f64>,
    month_usd: Option<f64>,
    targets: bool,
}

fn line(answer: &Map<String, Value>, name: &str, most: usize) -> Result<Option<String>, String> {
    match answer.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(said)) => {
            let said = said.trim();
            if said.chars().count() > most || said.contains(['\n', '\r']) {
                return Err(format!("`{name}` is one line of at most {most} characters"));
            }
            Ok((!said.is_empty()).then(|| said.to_owned()))
        }
        Some(_) => Err(format!("`{name}` is a line of text")),
    }
}

fn dollars(answer: &Map<String, Value>, name: &str) -> Result<Option<f64>, String> {
    let said = match answer.get(name) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Number(number)) => number.as_f64(),
        Some(Value::String(text)) if text.trim().is_empty() => return Ok(None),
        Some(Value::String(text)) => text.trim().parse::<f64>().ok(),
        Some(_) => None,
    };
    match said {
        Some(usd) if usd.is_finite() && usd > 0.0 && usd <= MOST_USD => Ok(Some(usd)),
        _ => Err(format!(
            "`{name}` is a number of dollars above 0 and at most {MOST_USD}"
        )),
    }
}

fn yes(answer: &Map<String, Value>, name: &str, unsaid: bool) -> Result<bool, String> {
    match answer.get(name) {
        None | Some(Value::Null) => Ok(unsaid),
        Some(Value::Bool(said)) => Ok(*said),
        Some(_) => Err(format!("`{name}` is true or false")),
    }
}

impl Read {
    fn of(wanted: &Wanted, answer: &Map<String, Value>) -> Result<Read, String> {
        let mut read = Read::default();
        if wanted.needed() {
            // The form said yes unless the person unticked it.
            read.switch_on = yes(answer, "switch_on", true)?;
        }
        if wanted.test.is_some() {
            read.test = line(answer, "test", 500)?;
        }
        if wanted.sandbox.is_some() {
            read.sandbox = match line(answer, "sandbox", 20)? {
                None => None,
                Some(word) => Some(
                    SandboxChoice::ALL
                        .iter()
                        .copied()
                        .find(|one| one.word() == word)
                        .ok_or_else(|| "`sandbox` is auto, bwrap, docker or off".to_owned())?,
                ),
            };
        }
        if wanted.image.is_some() {
            read.image = line(answer, "image", 200)?;
            if read
                .image
                .as_deref()
                .is_some_and(|image| !devflow_engine::sandbox::image_named(image))
            {
                return Err("`image` is a docker image's name".to_owned());
            }
        }
        if wanted.run_usd {
            read.run_usd = dollars(answer, "run_usd")?;
        }
        if wanted.month_usd {
            read.month_usd = dollars(answer, "month_usd")?;
        }
        if !wanted.targets.is_empty() {
            read.targets = yes(answer, "targets", false)?;
        }
        Ok(read)
    }
}

/// Why an answer was not applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotApplied {
    /// It does not read, or leaves devflow off: nothing was written.
    Unread(String),
    /// devflow.yaml was written, but what is kept on this machine was not.
    Partly(String),
}

impl std::fmt::Display for NotApplied {
    fn fmt(&self, to: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            NotApplied::Unread(why) => write!(to, "{why}"),
            NotApplied::Partly(why) => write!(to, "devflow.yaml was written, but {why}"),
        }
    }
}

/// What applying an answer did.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Applied {
    pub switched: bool,
    /// devflow.yaml's fields set, by dotted path.
    pub set: Vec<String>,
    /// The targets now confirmed.
    pub targets: Vec<String>,
}

impl Applied {
    pub fn to_json(&self) -> Value {
        json!({ "switched_on": self.switched, "set": self.set, "targets": self.targets })
    }
}

/// A dollar amount as devflow.yaml says it: whole when it is.
fn usd(amount: f64) -> Value {
    if amount.fract() == 0.0 && amount <= MOST_USD {
        json!(amount as u64)
    } else {
        json!(amount)
    }
}

/// Applies the person's answer to `wanted`: the file written, devflow
/// switched on here, the targets confirmed, each yes kept with `how` it
/// came. An answer that does not read, or that leaves devflow off where the
/// attack needs it on, writes nothing.
pub fn apply(
    project: &Project,
    consent: &Consent,
    wanted: &Wanted,
    answer: &Map<String, Value>,
    how: How,
    at: SystemTime,
) -> Result<Applied, NotApplied> {
    let read = Read::of(wanted, answer).map_err(NotApplied::Unread)?;
    if wanted.needed() && !read.switch_on {
        return Err(NotApplied::Unread(
            "the person left devflow off here".to_owned(),
        ));
    }
    let root = project.root.as_path();
    let mut changes: Vec<(String, Value)> = Vec::new();
    if wanted.switch && (wanted.file_off || wanted.setup) {
        changes.push(("enabled".to_owned(), json!(true)));
    }
    if wanted.stage {
        changes.push(("stages.attack.run".to_owned(), json!("release")));
    }
    if let Some(test) = &read.test {
        changes.push(("stages.attack.test".to_owned(), json!(test)));
    }
    if let Some(choice) = read.sandbox.filter(|one| *one != SandboxChoice::Auto) {
        changes.push(("stages.attack.sandbox".to_owned(), json!(choice.word())));
    }
    if let Some(image) = &read.image {
        changes.push(("stages.attack.image".to_owned(), json!(image)));
    }
    if let Some(amount) = read.run_usd {
        changes.push(("stages.attack.budget.run_usd".to_owned(), usd(amount)));
    }
    if let Some(amount) = read.month_usd {
        changes.push(("stages.attack.budget.month_usd".to_owned(), usd(amount)));
    }
    // The targets allowed: those confirmed before, and those just shown;
    // never one that was not. Worked out before anything is written.
    let allowed: Option<(Vec<String>, Pins)> = read.targets.then(|| {
        let before = devflow_engine::security::origins(&consent.confirmed_targets(root));
        let allowed: Vec<String> = wanted
            .listed
            .iter()
            .filter(|url| {
                wanted.targets.contains(url)
                    || devflow_engine::security::target(url)
                        .is_ok_and(|one| before.contains(&one.origin()))
            })
            .cloned()
            .collect();
        let pins = crate::cli::pins_after(
            &allowed,
            &wanted.targets,
            &consent.pinned(root),
            &wanted.found,
        );
        (allowed, pins)
    });
    // Every change checked before anything is written.
    let unread = NotApplied::Unread;
    let layout = project.layout();
    let planned = if wanted.setup {
        let detected = detect::detected(root, crate::flow::setup::machine(root));
        let made = proposal::setup_in(
            &layout,
            &State::Missing,
            Preset::Recommended,
            &Map::new(),
            &detected,
        )
        .map_err(|why| unread(why.to_string()))?;
        let state = State::Valid(made.yaml.clone(), Box::new(made.config.clone()));
        let changed = proposal::set_all_in(&layout, &state, &changes, true)
            .map_err(|why| unread(why.to_string()))?;
        devflow_engine::layers::layered(root, &changed.yaml, &crate::project::home())
            .map_err(|invalid| unread(invalid.to_string()))?;
        let mut files = made.files;
        files.retain(|file| !changed.files.iter().any(|one| one.path == file.path));
        files.extend(changed.files);
        Some(setup::with_unused(root, &changed.config, files))
    } else if !changes.is_empty() {
        let state = project.read();
        let changed = proposal::set_all_in(&layout, &state, &changes, true)
            .map_err(|why| unread(why.to_string()))?;
        devflow_engine::layers::layered(root, &changed.yaml, &crate::project::home())
            .map_err(|invalid| unread(invalid.to_string()))?;
        Some(setup::with_unused(
            root,
            &changed.config,
            changed.files.clone(),
        ))
    } else {
        None
    };
    if let Some(planned) = &planned {
        setup::write(root, planned).map_err(unread)?;
    }
    let set: Vec<String> = changes.iter().map(|(path, _)| path.clone()).collect();
    let mut yeses: Vec<&str> = Vec::new();
    if wanted.switch {
        yeses.push("enabled");
    }
    if set.iter().any(|path| path.starts_with("stages.attack.")) {
        yeses.push("stages.attack");
    }
    if allowed.is_some() {
        yeses.push("security.targets");
    }
    // What is kept on this machine, in one write.
    let parts = wanted.parts();
    consent
        .keep_answer(
            root,
            &crate::consent::Answered {
                switched_on: wanted.switch,
                targets: allowed
                    .as_ref()
                    .map(|(targets, pins)| (targets.as_slice(), pins)),
                yeses: &yeses,
                parts: &parts,
                how,
                asked_for: FOR,
                at,
            },
        )
        .map_err(|why| {
            let written = if planned.is_some() {
                NotApplied::Partly
            } else {
                NotApplied::Unread
            };
            written(format!(
                "devflow's switch on this machine was not kept: {why}"
            ))
        })?;
    Ok(Applied {
        switched: wanted.switch,
        set,
        targets: allowed.map(|(targets, _)| targets).unwrap_or_default(),
    })
}

/// The question as a terminal shows it: its message, then each field with
/// what it says now.
pub fn shown(message: &str, schema: &Value, answer: &Map<String, Value>) -> String {
    let mut lines = vec![message.to_owned(), String::new()];
    for (name, field) in schema["properties"].as_object().into_iter().flatten() {
        let value = answer.get(name).cloned().unwrap_or(Value::Null);
        let value = match value {
            Value::String(text) if text.is_empty() => "(empty)".to_owned(),
            Value::String(text) => text,
            Value::Null => "(empty)".to_owned(),
            other => other.to_string(),
        };
        lines.push(format!(
            "  {}: {value}",
            field["title"].as_str().unwrap_or(name)
        ));
        if let Some(about) = field["description"].as_str() {
            lines.push(format!("      {about}"));
        }
    }
    lines.join("\n")
}

/// What each field of the question starts at: its default, else nothing.
pub fn defaults(schema: &Value) -> Map<String, Value> {
    schema["properties"]
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(name, field)| field.get("default").map(|one| (name.clone(), one.clone())))
        .collect()
}

#[cfg(test)]
#[path = "ready_tests.rs"]
pub(crate) mod tests;
