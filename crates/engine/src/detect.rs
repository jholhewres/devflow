//! What a repository says about itself, read off its own files: the commands
//! that test, lint and run its E2E suite, each with the file and line it came
//! from, and the E2E tool, glossary and ADRs it keeps. Nothing is guessed: a
//! command is found in a file or it is not found. Given the `PATH` checks
//! run with, each is then validated (`available.rs`).
//!
//! The machine's half — the agent CLIs and the Decisions key — is handed in
//! by the app, which already knows it.

use std::path::Path;

use serde::Serialize;

use crate::config::{Agent, Report};

/// The most of one manifest read, checked before reading.
const MOST_BYTES: u64 = 1024 * 1024;

/// Where a JS or PHP runner writes its report, for the check to read.
const REPORT: &str = "$DEVFLOW_REPORT_DIR";

/// A command found in the repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Found {
    pub command: String,
    /// `file:line`.
    pub source: String,
    pub report: Report,
    /// Why it cannot run on this machine, when validation found it cannot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<String>,
}

/// A test command of a module in a subfolder, which the root's command does
/// not reach: a Go module of its own, say.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Nested {
    /// Relative to the root, `/` separated.
    pub folder: String,
    pub test: Found,
}

/// Folders a module is never looked for in: dependencies and build output.
const NOT_SEARCHED: [&str; 5] = ["node_modules", "vendor", ".git", "target", "dist"];
/// The most subfolders looked into, and the most modules kept.
const MOST_FOLDERS: usize = 200;
const MOST_NESTED: usize = 10;

/// An E2E tool the repository is set up for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct E2eTool {
    pub name: String,
    pub source: String,
    /// The command that runs Devflow's specs with it, when devpit writes
    /// that tool a config (`playwright.rs`).
    pub run: Option<String>,
}

/// An agent CLI on this machine, as the app found it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Cli {
    pub name: Agent,
    pub installed: bool,
    /// `None` when devpit has no way to tell.
    pub signed_in: Option<bool>,
}

/// What the app knows that the repository's files do not say.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Machine {
    pub clis: Vec<Cli>,
    pub decisions_key: bool,
    pub decisions_opted_out: bool,
    /// The repository's local branches, as git lists them.
    pub branches: Vec<String>,
    /// Its recent commits' subjects, newest first.
    pub subjects: Vec<String>,
    /// The skills already installed for the agent CLIs, by name.
    pub installed_skills: Vec<String>,
    /// The `PATH` checks run with; each command found is validated against
    /// it. `None` leaves them unvalidated.
    pub path: Option<std::ffi::OsString>,
}

/// How the repository already works, as hints for a setup: nothing is
/// configured from them by itself.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Hints {
    /// CLAUDE.md, AGENTS.md and CONTRIBUTING.md, where they are.
    pub guides: Vec<String>,
    pub pr_templates: Vec<String>,
    pub issue_templates: Vec<String>,
    /// git-flow's branches, when it has `develop` beside them.
    pub branches: Vec<String>,
    /// The ticket keys its commits name, most used first, such as `LED`.
    pub ticket_keys: Vec<String>,
    /// Skills an own stage can use where they are: `skills/<name>`.
    pub skills: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Detected {
    pub test: Vec<Found>,
    pub e2e: Vec<Found>,
    pub lint: Vec<Found>,
    pub typecheck: Vec<Found>,
    /// Modules in subfolders, at depth 1 and 2.
    pub nested: Vec<Nested>,
    pub e2e_tools: Vec<E2eTool>,
    pub clis: Vec<Cli>,
    pub decisions_key: bool,
    pub decisions_opted_out: bool,
    pub glossary: Option<String>,
    pub adrs: Vec<String>,
    pub hints: Hints,
}

impl Detected {
    /// Every command found, with the kind of check it would be.
    pub fn every(&self) -> impl Iterator<Item = (&Found, &'static str)> {
        let kinds = [
            ("test", &self.test),
            ("e2e", &self.e2e),
            ("lint", &self.lint),
            ("typecheck", &self.typecheck),
        ];
        kinds
            .into_iter()
            .flat_map(|(kind, all)| all.iter().map(move |one| (one, kind)))
            .chain(self.nested.iter().map(|one| (&one.test, "test")))
    }

    pub(crate) fn every_mut(&mut self) -> impl Iterator<Item = &mut Found> {
        self.test
            .iter_mut()
            .chain(&mut self.e2e)
            .chain(&mut self.lint)
            .chain(&mut self.typecheck)
            .chain(self.nested.iter_mut().map(|one| &mut one.test))
    }
}

/// Everything detected about the project at `root`.
pub fn detected(root: &Path, machine: Machine) -> Detected {
    let files = Files { root };
    let hints = hints(root, &files, &machine);
    let path = machine.path;
    let mut found = Detected {
        hints,
        test: Vec::new(),
        e2e: Vec::new(),
        lint: Vec::new(),
        typecheck: Vec::new(),
        nested: nested(root, &files),
        e2e_tools: e2e_tools(&files),
        clis: machine.clis,
        decisions_key: machine.decisions_key,
        decisions_opted_out: machine.decisions_opted_out,
        glossary: ["GLOSSARY.md", "CONTEXT.md"]
            .into_iter()
            .find(|name| files.read(name).is_some())
            .map(str::to_owned),
        adrs: adrs(root),
    };
    makefile(&files, &mut found);
    package_json(&files, &mut found);
    cargo(&files, &mut found);
    pyproject(&files, &mut found);
    go(&files, &mut found);
    composer(&files, &mut found);
    if let Some(path) = path {
        crate::available::validated(root, &path, &mut found);
    }
    found
}

/// The project's files, each read only once it is resolved inside the root.
struct Files<'a> {
    root: &'a Path,
}

impl Files<'_> {
    fn read(&self, name: &str) -> Option<String> {
        let path = crate::fsguard::resolve(self.root, name).ok()?;
        let meta = std::fs::metadata(&path).ok()?;
        if !meta.is_file() || meta.len() > MOST_BYTES {
            return None;
        }
        std::fs::read_to_string(path).ok()
    }

    fn any(&self, names: &[&str]) -> Option<String> {
        names
            .iter()
            .find(|name| self.read(name).is_some())
            .map(|name| (*name).to_owned())
    }
}

/// The line `needle` first appears on, from 1, else the first.
fn line_of(text: &str, needle: &str) -> usize {
    text.lines()
        .position(|line| line.contains(needle))
        .map_or(1, |at| at + 1)
}

fn found(command: String, file: &str, line: usize, report: Report) -> Found {
    Found {
        command,
        source: format!("{file}:{line}"),
        report,
        unavailable: None,
    }
}

fn makefile(files: &Files, into: &mut Detected) {
    let Some((name, text)) = ["Makefile", "makefile", "GNUmakefile"]
        .into_iter()
        .find_map(|name| files.read(name).map(|text| (name, text)))
    else {
        return;
    };
    let target = |wanted: &[&str]| {
        text.lines().enumerate().find_map(|(at, line)| {
            let (head, rest) = line.split_once(':')?;
            let head = head.trim_end();
            (wanted.contains(&head) && !rest.starts_with('=') && !line.starts_with(['\t', ' ']))
                .then(|| (head.to_owned(), at + 1))
        })
    };
    // Where a make target leaves a report is unknown, so it is said to keep none.
    if let Some((target, line)) = target(&["test", "tests"]) {
        into.test
            .push(found(format!("make {target}"), name, line, Report::Nothing));
    }
    if let Some((target, line)) = target(&["e2e", "test-e2e", "e2e-test"]) {
        into.e2e
            .push(found(format!("make {target}"), name, line, Report::Nothing));
    }
    if let Some((target, line)) = target(&["lint"]) {
        into.lint
            .push(found(format!("make {target}"), name, line, Report::Nothing));
    }
}

/// How the project runs a package's binary, and its package manager, by its lockfile.
fn runner(files: &Files) -> (&'static str, &'static str) {
    if files.read("pnpm-lock.yaml").is_some() {
        ("pnpm exec", "pnpm")
    } else if files.read("yarn.lock").is_some() {
        ("yarn", "yarn")
    } else if files.any(&["bun.lock", "bun.lockb"]).is_some() {
        ("bunx", "bun")
    } else {
        ("npx", "npm")
    }
}

fn package_json(files: &Files, into: &mut Detected) {
    const FILE: &str = "package.json";
    let Some(text) = files.read(FILE) else {
        return;
    };
    let Ok(package) = serde_json::from_str::<serde_json::Value>(&text) else {
        return;
    };
    let has = |name: &str| {
        ["dependencies", "devDependencies"]
            .iter()
            .any(|deps| package.get(deps).and_then(|deps| deps.get(name)).is_some())
    };
    let script = |name: &str| {
        package
            .get("scripts")
            .and_then(|scripts| scripts.get(name))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    let (exec, manager) = runner(files);
    let report = format!("--outputFile=\"{REPORT}/tests.json\"");
    let script_line = |name: &str| line_of(&text, &format!("\"{name}\""));
    let test = if has("vitest") {
        Some((
            format!("{exec} vitest run --reporter=default --reporter=json {report}"),
            line_of(&text, "\"vitest\""),
            Report::Vitest,
        ))
    } else if has("jest") {
        Some((
            format!("{exec} jest --json {report}"),
            line_of(&text, "\"jest\""),
            Report::Jest,
        ))
    } else {
        script("test").map(|_| {
            (
                format!("{manager} test"),
                script_line("test"),
                Report::Nothing,
            )
        })
    };
    if let Some((command, line, report)) = test {
        into.test.push(found(command, FILE, line, report));
    }
    if let Some(name) = ["e2e", "test:e2e", "e2e:test"]
        .into_iter()
        .find(|name| script(name).is_some())
    {
        into.e2e.push(found(
            format!("{manager} run {name}"),
            FILE,
            script_line(name),
            Report::Nothing,
        ));
    }
    if script("lint").is_some() {
        into.lint.push(found(
            format!("{manager} run lint"),
            FILE,
            script_line("lint"),
            Report::Nothing,
        ));
    }
    if typechecked_by_tsc(
        has("typescript"),
        files.read("tsconfig.json").is_some(),
        ["typecheck", "type-check"]
            .into_iter()
            .any(|name| script(name).is_some()),
    ) {
        into.typecheck.push(found(
            format!("{exec} tsc --noEmit"),
            FILE,
            line_of(&text, "\"typescript\""),
            Report::Nothing,
        ));
    }
}

/// Whether a project gets `tsc --noEmit` as its typecheck: TypeScript with a
/// tsconfig, and no script of its own that already does it.
pub(crate) fn typechecked_by_tsc(typescript: bool, tsconfig: bool, script: bool) -> bool {
    typescript && tsconfig && !script
}

fn cargo(files: &Files, into: &mut Detected) {
    const FILE: &str = "Cargo.toml";
    let Some(text) = files.read(FILE) else {
        return;
    };
    let line = text
        .lines()
        .position(|line| line.trim() == "[package]" || line.trim() == "[workspace]")
        .map_or(1, |at| at + 1);
    into.test
        .push(found("cargo test".to_owned(), FILE, line, Report::Cargo));
    into.lint.push(found(
        "cargo clippy --all-targets -- -D warnings".to_owned(),
        FILE,
        line,
        Report::Nothing,
    ));
}

fn pyproject(files: &Files, into: &mut Detected) {
    const FILE: &str = "pyproject.toml";
    let Some(text) = files.read(FILE) else {
        return;
    };
    let runner = if files.read("uv.lock").is_some() {
        "uv run "
    } else if files.read("poetry.lock").is_some() {
        "poetry run "
    } else {
        ""
    };
    if text.contains("[tool.pytest") || text.contains("pytest") {
        let line = line_of(&text, "pytest");
        into.test.push(found(
            format!("{runner}python -m pytest --junitxml=\"{REPORT}/pytest.xml\""),
            FILE,
            line,
            Report::Junit,
        ));
    }
    if text.contains("[tool.ruff") {
        into.lint.push(found(
            format!("{runner}ruff check ."),
            FILE,
            line_of(&text, "[tool.ruff"),
            Report::Nothing,
        ));
    }
}

fn go(files: &Files, into: &mut Detected) {
    const FILE: &str = "go.mod";
    if files.read(FILE).is_none() {
        return;
    }
    into.test.push(found(
        format!("go test -json ./... > \"{REPORT}/go-test.json\""),
        FILE,
        1,
        Report::Go,
    ));
    let lint = match files.any(&[".golangci.yml", ".golangci.yaml", ".golangci.toml"]) {
        Some(config) => found("golangci-lint run".to_owned(), &config, 1, Report::Nothing),
        None => found("go vet ./...".to_owned(), FILE, 1, Report::Nothing),
    };
    into.lint.push(lint);
}

/// The Go modules in subfolders at depth 1 and 2, each tested from the root
/// with `go -C`: `go test ./...` at the root stops at a module's edge.
fn nested(root: &Path, files: &Files) -> Vec<Nested> {
    let mut kept = Vec::new();
    for folder in subfolders(root) {
        if kept.len() == MOST_NESTED {
            break;
        }
        let module = format!("{folder}/go.mod");
        if files.read(&module).is_some() {
            kept.push(Nested {
                test: found(
                    format!("go -C {folder} test -json ./... > \"{REPORT}/go-test.json\""),
                    &module,
                    1,
                    Report::Go,
                ),
                folder,
            });
        }
    }
    kept
}

/// The project's folders at depth 1 and 2, sorted, never into dependencies,
/// build output or a hidden folder, and never through a link. A name that
/// would be shell syntax in a command is left out.
pub(crate) fn subfolders(root: &Path) -> Vec<String> {
    let folders_in = |relative: &str| -> Vec<String> {
        let Ok(folder) = crate::fsguard::resolve(root, relative) else {
            return Vec::new();
        };
        let Ok(entries) = std::fs::read_dir(folder) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| plain_folder(name) && !NOT_SEARCHED.contains(&name.as_str()))
            .collect();
        names.sort();
        names
    };
    let mut all = Vec::new();
    for first in folders_in(".") {
        let deeper = folders_in(&first);
        all.push(first.clone());
        all.extend(deeper.into_iter().map(|name| format!("{first}/{name}")));
        if all.len() >= MOST_FOLDERS {
            all.truncate(MOST_FOLDERS);
            break;
        }
    }
    all
}

/// A folder name a command can carry unquoted.
fn plain_folder(name: &str) -> bool {
    !name.starts_with(['.', '-'])
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn composer(files: &Files, into: &mut Detected) {
    const FILE: &str = "composer.json";
    let Some(text) = files.read(FILE) else {
        return;
    };
    let Ok(composer) = serde_json::from_str::<serde_json::Value>(&text) else {
        return;
    };
    let has = |name: &str| {
        ["require", "require-dev"]
            .iter()
            .any(|deps| composer.get(deps).and_then(|deps| deps.get(name)).is_some())
    };
    let script = |name: &str| {
        composer
            .get("scripts")
            .and_then(|scripts| scripts.get(name))
            .is_some()
    };
    if script("test") {
        into.test.push(found(
            "composer test".to_owned(),
            FILE,
            line_of(&text, "\"test\""),
            Report::Nothing,
        ));
    } else if has("pestphp/pest") {
        into.test.push(found(
            format!("vendor/bin/pest --log-junit \"{REPORT}/pest.xml\""),
            FILE,
            line_of(&text, "\"pestphp/pest\""),
            Report::Junit,
        ));
    } else if has("phpunit/phpunit") {
        into.test.push(found(
            format!("vendor/bin/phpunit --log-junit \"{REPORT}/phpunit.xml\""),
            FILE,
            line_of(&text, "\"phpunit/phpunit\""),
            Report::Junit,
        ));
    }
    if script("lint") {
        into.lint.push(found(
            "composer lint".to_owned(),
            FILE,
            line_of(&text, "\"lint\""),
            Report::Nothing,
        ));
    } else if has("phpstan/phpstan") {
        into.lint.push(found(
            "vendor/bin/phpstan analyse".to_owned(),
            FILE,
            line_of(&text, "\"phpstan/phpstan\""),
            Report::Nothing,
        ));
    } else if has("squizlabs/php_codesniffer") {
        into.lint.push(found(
            "vendor/bin/phpcs".to_owned(),
            FILE,
            line_of(&text, "\"squizlabs/php_codesniffer\""),
            Report::Nothing,
        ));
    }
    if script("e2e") {
        into.e2e.push(found(
            "composer e2e".to_owned(),
            FILE,
            line_of(&text, "\"e2e\""),
            Report::Nothing,
        ));
    }
}

fn e2e_tools(files: &Files) -> Vec<E2eTool> {
    let package = files.read("package.json").unwrap_or_default();
    let mut tools = Vec::new();
    for (name, configs, dependency) in [
        (
            "playwright",
            &[
                "playwright.config.ts",
                "playwright.config.js",
                "playwright.config.mjs",
                "playwright.config.cjs",
            ][..],
            "\"@playwright/test\"",
        ),
        (
            "cypress",
            &[
                "cypress.config.ts",
                "cypress.config.js",
                "cypress.config.mjs",
                "cypress.config.cjs",
                "cypress.json",
            ][..],
            "\"cypress\"",
        ),
    ] {
        let source = files.any(configs).or_else(|| {
            package
                .contains(dependency)
                .then(|| format!("package.json:{}", line_of(&package, dependency)))
        });
        if let Some(source) = source {
            tools.push(E2eTool {
                run: (name == crate::playwright::TOOL)
                    .then(|| crate::playwright::command(runner(files).0)),
                name: name.to_owned(),
                source,
            });
        }
    }
    tools
}

/// The names of the files in the folder `relative` of the project, sorted.
fn listed(root: &Path, relative: &str) -> Vec<String> {
    let Ok(folder) = crate::fsguard::resolve(root, relative) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(folder) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| !name.starts_with('.'))
        .map(|name| format!("{relative}/{name}"))
        .collect();
    names.sort();
    names.truncate(20);
    names
}

/// The keys `KEY-123` names in `subjects`, most used first.
pub fn ticket_keys(subjects: &[String]) -> Vec<String> {
    let mut counted: Vec<(String, usize)> = Vec::new();
    for subject in subjects {
        let bytes = subject.as_bytes();
        let mut at = 0;
        while at < bytes.len() {
            let starts = bytes[at].is_ascii_uppercase()
                && (at == 0 || !bytes[at - 1].is_ascii_alphanumeric());
            if !starts {
                at += 1;
                continue;
            }
            let key_end = (at..bytes.len())
                .find(|end| !(bytes[*end].is_ascii_uppercase() || bytes[*end].is_ascii_digit()))
                .unwrap_or(bytes.len());
            let digits_end = (key_end + 1..bytes.len())
                .find(|end| !bytes[*end].is_ascii_digit())
                .unwrap_or(bytes.len());
            let key = &subject[at..key_end];
            if (2..=10).contains(&key.len())
                && bytes.get(key_end) == Some(&b'-')
                && digits_end > key_end + 1
                && bytes
                    .get(digits_end)
                    .is_none_or(|next| !next.is_ascii_alphanumeric())
            {
                match counted.iter_mut().find(|(seen, _)| seen == key) {
                    Some((_, count)) => *count += 1,
                    None => counted.push((key.to_owned(), 1)),
                }
            }
            at = key_end.max(at + 1);
        }
    }
    counted.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    counted.into_iter().take(5).map(|(key, _)| key).collect()
}

/// Whether `relative` exists under that exact spelling. On a case-insensitive
/// disk (macOS, Windows) `PULL_REQUEST_TEMPLATE.md` also opens
/// `pull_request_template.md`, and one file must not be reported twice.
fn spelled_as(root: &Path, relative: &str) -> bool {
    let (folder, name) = relative.rsplit_once('/').unwrap_or(("", relative));
    let Ok(folder) = crate::fsguard::resolve(root, if folder.is_empty() { "." } else { folder })
    else {
        return false;
    };
    std::fs::read_dir(folder).is_ok_and(|entries| {
        entries
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_str() == Some(name))
    })
}

fn hints(root: &Path, files: &Files, machine: &Machine) -> Hints {
    let present = |names: &[&str]| -> Vec<String> {
        names
            .iter()
            .filter(|name| files.read(name).is_some() && spelled_as(root, name))
            .map(|name| (*name).to_owned())
            .collect()
    };
    let mut pr_templates = present(&[
        ".github/pull_request_template.md",
        ".github/PULL_REQUEST_TEMPLATE.md",
        "PULL_REQUEST_TEMPLATE.md",
        "docs/pull_request_template.md",
    ]);
    pr_templates.extend(listed(root, ".github/PULL_REQUEST_TEMPLATE"));
    pr_templates.extend(listed(root, ".gitlab/merge_request_templates"));
    let mut issue_templates = present(&[".github/issue_template.md", ".github/ISSUE_TEMPLATE.md"]);
    issue_templates.extend(listed(root, ".github/ISSUE_TEMPLATE"));
    issue_templates.extend(listed(root, ".gitlab/issue_templates"));
    let flow = ["release/", "feature/", "hotfix/"];
    let branches = if machine.branches.iter().any(|name| name == "develop") {
        machine
            .branches
            .iter()
            .filter(|name| *name == "develop" || flow.iter().any(|prefix| name.starts_with(prefix)))
            .take(10)
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    let mut skills: Vec<String> = listed(root, ".claude/skills")
        .into_iter()
        .filter_map(|path| path.rsplit('/').next().map(str::to_owned))
        .chain(machine.installed_skills.iter().cloned())
        .filter(|name| crate::config::is_name(name))
        .collect();
    skills.sort();
    skills.dedup();
    Hints {
        guides: present(&[
            "CLAUDE.md",
            "AGENTS.md",
            "CONTRIBUTING.md",
            ".github/CONTRIBUTING.md",
        ]),
        pr_templates,
        issue_templates,
        branches,
        ticket_keys: ticket_keys(&machine.subjects),
        skills,
    }
}

/// The ADRs under `docs/adr/`, by name.
fn adrs(root: &Path) -> Vec<String> {
    let Ok(folder) = crate::fsguard::resolve(root, "docs/adr") else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(folder) else {
        return Vec::new();
    };
    let mut found: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.ends_with(".md"))
        .map(|name| format!("docs/adr/{name}"))
        .collect();
    found.sort();
    found
}

/// What detection could not settle and the person has to: one sentence each.
pub fn open(detected: &Detected) -> Vec<String> {
    let mut open = Vec::new();
    match detected.test.as_slice() {
        [] => open.push("no test command was found".to_owned()),
        [first, rest @ ..] if !rest.is_empty() && !first.command.starts_with("make ") => {
            let said: Vec<String> = detected
                .test
                .iter()
                .map(|one| format!("{} ({})", one.command, one.source))
                .collect();
            open.push(format!(
                "{} test commands found: {}",
                said.len(),
                said.join(" and ")
            ));
        }
        _ => {}
    }
    if detected.e2e.is_empty() {
        for tool in &detected.e2e_tools {
            open.push(format!(
                "{} is set up ({}), but no command in the repo runs it",
                tool.name, tool.source
            ));
        }
    }
    for cli in &detected.clis {
        if cli.installed && cli.signed_in == Some(false) {
            open.push(format!(
                "{} is installed but not signed in, so it cannot review",
                cli.name.word()
            ));
        }
    }
    for (one, kind) in detected.every() {
        if let Some(why) = &one.unavailable {
            open.push(format!(
                "`{}` ({}) cannot run here, so it is not recommended as the {kind} check: {why}",
                one.command, one.source
            ));
        }
    }
    if detected.decisions_key && detected.decisions_opted_out {
        open.push("a Decisions key is kept, but this project is opted out of Decisions".to_owned());
    }
    open
}

#[cfg(test)]
#[path = "detect_tests.rs"]
mod tests;
