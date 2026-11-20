//! What an attack needs that only the person gives: devflow switched on in
//! the project, the attack stage on, the command that runs one exploit test,
//! and the targets it may reach. Asked as one question, as short as it can
//! be: what devflow found (the command, the sandbox, a docker image) is said
//! in its text, and a field is asked only for what has no safe default.
//! Through the client (MCP's `elicitation/create`), or, where the client
//! cannot ask, by one command on a terminal. Either way the answer is
//! applied here: devflow.yaml edited in place, keeping what devpit or the
//! person wrote, and each yes kept in consent.json with how it came. A
//! budget is never asked: the attack runs on the person's own CLI, most
//! often a subscription, and `stages.attack.budget` is theirs to set.

use std::ffi::OsStr;
use std::path::Path;
use std::time::SystemTime;

use devflow_engine::config::{Budget, Config, SandboxChoice};
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
/// What the attack's question of devflow 0.6.2 and 0.6.3 filled the budget
/// in with, in cents: per attack, and per calendar month.
const PREFILLED_RUN_CENTS: u64 = 500;
const PREFILLED_MONTH_CENTS: u64 = 5_000;
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
    /// `stages.attack.test` is not set: the command detected, written on a
    /// yes, or `None`, asked.
    pub test: Option<Option<ExploitTest>>,
    /// Where the exploits run: the sandbox set, else what `auto` finds here,
    /// `bwrap`, `docker`, or `nothing`. Said, never asked.
    pub sandbox: Option<String>,
    /// `stages.attack.image` is not set and docker is here: the image
    /// suggested for the project's runner, written on a yes, or empty when
    /// there is none, asked only where docker is the sandbox.
    pub image: Option<String>,
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
        self.test.is_some() || self.image_part() || !self.targets.is_empty()
    }

    /// The image is part of the question: found, and written on a yes, or
    /// asked.
    fn image_part(&self) -> bool {
        self.image.as_deref().is_some_and(|image| !image.is_empty()) || self.image_asked()
    }

    /// The image asked for: docker is the sandbox, and none is suggested.
    fn image_asked(&self) -> bool {
        self.image.as_deref() == Some("") && self.sandbox.as_deref() == Some("docker")
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
        let mut parts: Vec<String> = [("test", self.test.is_some()), ("image", self.image_part())]
            .into_iter()
            .filter(|(_, asked)| *asked)
            .map(|(name, _)| name.to_owned())
            .collect();
        if !self.targets.is_empty() {
            parts.push(self.targets_part.clone());
        }
        parts
    }

    /// The question, said once: its message and its form. What devflow found
    /// is said in the message and written on a yes; a field is asked only
    /// for what has no safe default, so most often there is none, and the
    /// question is its message, accepted or declined.
    pub fn question(&self, project: &Project) -> (String, Value) {
        let mut doing: Vec<String> = Vec::new();
        if self.setup {
            doing.push(format!(
                "writes {} (yours to commit)",
                project.layout().file
            ));
        }
        if self.switch {
            doing.push("switches devflow on here".to_owned());
        }
        if self.stage {
            doing.push("turns the attack stage on, for attacks asked by name".to_owned());
        }
        if let Some(Some(found)) = &self.test {
            doing.push(format!(
                "sets the exploit test to `{}` (from {})",
                found.command, found.source
            ));
        }
        if let Some(image) = self.image.as_deref().filter(|image| !image.is_empty()) {
            doing.push(format!("sets the docker image to {image}"));
        }
        let name = project.root.file_name().map_or_else(
            || project.root.display().to_string(),
            |name| name.to_string_lossy().into_owned(),
        );
        let mut said = vec![if doing.is_empty() {
            format!("devflow's attack on {name} needs your answer.")
        } else {
            format!("devflow's attack on {name}: accepting {}.", listed(&doing))
        }];
        match self.sandbox.as_deref() {
            Some("nothing") => {
                said.push("No sandbox here: the session runs each exploit.".to_owned())
            }
            Some(found) => said.push(format!("Exploits run in {found}, offline.")),
            None => {}
        }
        said.push("Nothing is committed; declining changes nothing.".to_owned());
        let mut fields = Map::new();
        if let Some(None) = &self.test {
            fields.insert(
                "test".to_owned(),
                json!({ "type": "string", "title": "Exploit test command", "maxLength": 500,
                    "description": "No test runner was found here. The command that runs one exploit test, given its path as $DEVFLOW_EXPLOIT and its name as $DEVFLOW_EXPLOIT_TEST. Empty: the session runs each exploit." }),
            );
        }
        if self.image_asked() {
            fields.insert(
                "image".to_owned(),
                json!({ "type": "string", "title": "Docker image", "maxLength": 200,
                    "description": "Docker is the sandbox here, and no image was found for the project's runner: the image each exploit test runs in. Empty: none is set, and the session runs each exploit." }),
            );
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

/// `a`, `a and b`, `a, b and c`.
fn listed(said: &[String]) -> String {
    match said {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
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
        // docker, short of an image: the one thing then asked.
        Err(_) if docker => "docker",
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
        sandbox: Some(
            match attack.sandbox {
                None | Some(SandboxChoice::Auto) => here,
                Some(SandboxChoice::Bwrap) => "bwrap",
                Some(SandboxChoice::Docker) => "docker",
                Some(SandboxChoice::Off) => "nothing",
            }
            .to_owned(),
        ),
        image: (attack.image.is_none() && docker && open("image"))
            .then(|| suggested.unwrap_or_default().to_owned()),
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
    test: Option<String>,
    image: Option<String>,
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

fn yes(answer: &Map<String, Value>, name: &str, unsaid: bool) -> Result<bool, String> {
    match answer.get(name) {
        None | Some(Value::Null) => Ok(unsaid),
        Some(Value::Bool(said)) => Ok(*said),
        Some(_) => Err(format!("`{name}` is true or false")),
    }
}

impl Read {
    /// What a yes writes: what devflow found, and what the person filled in
    /// for the rest. A field that was not asked is not read.
    fn of(wanted: &Wanted, answer: &Map<String, Value>) -> Result<Read, String> {
        let mut read = Read::default();
        match &wanted.test {
            Some(Some(found)) => read.test = Some(found.command.clone()),
            Some(None) => read.test = line(answer, "test", 500)?,
            None => {}
        }
        if wanted.image_asked() {
            read.image = line(answer, "image", 200)?;
            if read
                .image
                .as_deref()
                .is_some_and(|image| !devflow_engine::sandbox::image_named(image))
            {
                return Err("`image` is a docker image's name".to_owned());
            }
        } else if let Some(image) = wanted.image.as_deref().filter(|image| !image.is_empty()) {
            read.image = Some(image.to_owned());
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

/// Applies the person's answer to `wanted`: the file written, devflow
/// switched on here, the targets confirmed, each yes kept with `how` it
/// came. A yes is the person's: accepting the question is what switches
/// devflow on. An answer that does not read writes nothing.
pub fn apply(
    project: &Project,
    consent: &Consent,
    wanted: &Wanted,
    answer: &Map<String, Value>,
    how: How,
    at: SystemTime,
) -> Result<Applied, NotApplied> {
    let read = Read::of(wanted, answer).map_err(NotApplied::Unread)?;
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
    if let Some(image) = &read.image {
        changes.push(("stages.attack.image".to_owned(), json!(image)));
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

/// The parts of `budget` the attack's question of devflow 0.6.2 and 0.6.3
/// filled in with what it started at (US$ 5 per attack, US$ 50 a month) in
/// a project where consent.json says it asked them. The person never chose
/// them, and most pay their CLI by subscription, so they no longer hold the
/// attack; one the person changed, or wrote, still does.
pub fn prefilled(root: &Path, consent: &Consent, budget: Budget) -> Budget {
    let answered = consent.answered(root);
    Budget {
        run_cents: budget
            .run_cents
            .filter(|cents| *cents == PREFILLED_RUN_CENTS && answered.contains("run_usd")),
        month_cents: budget
            .month_cents
            .filter(|cents| *cents == PREFILLED_MONTH_CENTS && answered.contains("month_usd")),
    }
}

/// A budget as a person reads it.
pub fn described(budget: Budget) -> String {
    let mut said = Vec::new();
    if let Some(cents) = budget.run_cents {
        said.push(format!("US$ {} per attack", Budget::usd(cents)));
    }
    if let Some(cents) = budget.month_cents {
        said.push(format!("US$ {} a month", Budget::usd(cents)));
    }
    said.join(", ")
}

/// `budget` as it holds the attack: without what the question prefilled.
pub fn in_force(root: &Path, consent: &Consent, budget: Budget) -> Budget {
    let filled = prefilled(root, consent, budget);
    Budget {
        run_cents: budget.run_cents.filter(|_| filled.run_cents.is_none()),
        month_cents: budget.month_cents.filter(|_| filled.month_cents.is_none()),
    }
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
