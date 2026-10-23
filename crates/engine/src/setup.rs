//! What a setup leaves in `.devpit/devflow/`: devflow.yaml, one script per
//! check, a `.gitignore` for a check run by hand, and a Playwright config
//! when the project runs Playwright. The reviewer personas and the findings
//! schema are devpit's and stay in devpit: a project holds only a persona it
//! made its own, under a name of its own. Previewed first, written only when
//! asked, and never committed.

use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::folder::{Layout, DIR};

/// The personas, as this build ships them.
pub(crate) const PERSONAS: [(&str, &str); 4] = [
    (
        "devflow-spec",
        include_str!("../../../flow/personas/devflow-spec.md"),
    ),
    (
        "devflow-standards",
        include_str!("../../../flow/personas/devflow-standards.md"),
    ),
    (
        "devflow-security",
        include_str!("../../../flow/personas/devflow-security.md"),
    ),
    // Every axis in one reading, for a review `review.scale` sized down.
    (
        "devflow-all",
        include_str!("../../../flow/personas/devflow-all.md"),
    ),
];

/// SHA-256 of every text a devpit release shipped for a persona, by name.
/// The setup copied them into projects once: a copy still one of these is
/// devpit's default, not the person's, and is read from devpit instead, so
/// an old text never outlives the release that replaced it.
const SHIPPED: [(&str, &str); 16] = [
    (
        "devflow-spec",
        "40b270801839a2e79d7acfbbaeb6ef83530c706f0dd9c27f09588277bccbc710",
    ),
    (
        "devflow-spec",
        "141a02169cd34705791dce505f7a7cac98ffbf88f8be6b7c6240ea047ff7340f",
    ),
    (
        "devflow-spec",
        "8d171a41e5e73a9d48633068a4205d8191efaef43bbddc36aef846f4a14844b4",
    ),
    (
        "devflow-spec",
        "02d06643e806befcf736691db93a0e31dad06a0ba206ebf309afa9b2c3965c55",
    ),
    (
        "devflow-spec",
        "0e84bd8fcc06cc438783d984c2763ce195912ce7a970489c596e61804f41d1a4",
    ),
    (
        "devflow-standards",
        "6a015556578ad4dc0ccf58ce6271e7bda9946326e6202ed82e9907c2ecbd871e",
    ),
    (
        "devflow-standards",
        "ba55083b7d3b4e2c4587c6d85350ea36533281c8f050ee9ec62c248b47bcf538",
    ),
    (
        "devflow-standards",
        "bae2a29b386f8a22755f052879521600b779e4ca3d061871e95650e60fa5782c",
    ),
    (
        "devflow-standards",
        "6c4e3dbad877dc812f4370e44b501330da1030c9f4f02a4d06a636925a0ca3ef",
    ),
    (
        "devflow-security",
        "950bc4a1142ae6b037ea7090e4e890d90d3368d8db5b243594d9cc87c0bc2e3e",
    ),
    (
        "devflow-security",
        "3257393088653ddcd25a8b3e2f1ca7ab84a68914169d5c547c32fb988282a464",
    ),
    (
        "devflow-security",
        "1e5e6383cdedd2783b7ca5d77a2fd49e4e7c8bb85001acb384089d275a93b9b6",
    ),
    (
        "devflow-security",
        "1106241b7c1a0caa87ef02745dd580b3878c9d28194b67f4036314cbe1c60569",
    ),
    (
        "devflow-all",
        "dd7bf263271b5d641328c37e1dddf9e152f21d1528f1e0bb3409d6889107c072",
    ),
    (
        "devflow-all",
        "5c2674452e08c8fc099ceebbf005e39465d18ce28f97a38659cd666f0f233f6f",
    ),
    (
        "devflow-all",
        "0ca5f880eac84d1490e9417779c05aa5a317625c45bcace65fd15f81ada7b7e6",
    ),
];

/// Whether `text` is a persona text devpit shipped as `name`: a copy the
/// person never changed. Line endings a checkout rewrote do not count.
pub(crate) fn shipped(name: &str, text: &str) -> bool {
    let digest = format!(
        "{:x}",
        Sha256::digest(text.replace("\r\n", "\n").as_bytes())
    );
    SHIPPED
        .iter()
        .any(|(shipped, sum)| *shipped == name && *sum == digest)
}

/// The line the `.gitignore` needs: a check run by hand reports there.
const IGNORED: &str = "runs/";

/// A check's command, kept in a script of its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Script {
    pub name: String,
    pub command: String,
    /// Where the command was found, when detection found it.
    pub source: Option<String>,
}

/// How a check runs its script, from the project's root. Through `sh`, so a
/// checkout that lost the executable bit still runs it.
pub fn script_run(name: &str) -> String {
    script_run_in(DIR, name)
}

/// [`script_run`] for a script in the folder `dir`.
pub fn script_run_in(dir: &str, name: &str) -> String {
    format!("sh {dir}/scripts/check-{name}.sh")
}

/// `config` with every check that runs a command of its own running a script
/// instead, and the scripts to write. `sources` says where a command was found.
pub fn scripted(config: Config, sources: &[(String, String)]) -> (Config, Vec<Script>) {
    scripted_but(DIR, config, sources, &[])
}

/// [`scripted`] for scripts in the folder `dir`.
pub fn scripted_in(
    dir: &str,
    config: Config,
    sources: &[(String, String)],
) -> (Config, Vec<Script>) {
    scripted_but(dir, config, sources, &[])
}

/// [`scripted`] for a change: only the checks not among `had` move into a
/// script, so a command the person wrote in devflow.yaml stays theirs.
pub fn scripted_new(config: Config, had: &[String]) -> (Config, Vec<Script>) {
    scripted_but(DIR, config, &[], had)
}

/// [`scripted_new`] for scripts in the folder `dir`.
pub fn scripted_new_in(dir: &str, config: Config, had: &[String]) -> (Config, Vec<Script>) {
    scripted_but(dir, config, &[], had)
}

fn scripted_but(
    dir: &str,
    mut config: Config,
    sources: &[(String, String)],
    had: &[String],
) -> (Config, Vec<Script>) {
    let mut scripts = Vec::new();
    for check in &mut config.stages.execution.checks {
        let run = script_run_in(dir, &check.name);
        if check.run == run || had.contains(&check.name) {
            continue;
        }
        scripts.push(Script {
            name: check.name.clone(),
            source: sources
                .iter()
                .find(|(command, _)| *command == check.run)
                .map(|(_, source)| source.clone()),
            command: std::mem::replace(&mut check.run, run),
        });
    }
    (config, scripts)
}

fn script_text(dir: &str, script: &Script) -> String {
    // From `<dir>/scripts/` back up to the root.
    let up = vec![".."; dir.split('/').count() + 1].join("/");
    let from = script
        .source
        .as_deref()
        .map(|source| format!(", found in {source}"))
        .unwrap_or_default();
    format!(
        "#!/bin/sh\n\
         # Devflow check `{name}`{from}.\n\
         # It runs from the project's root, wherever it is started; a report\n\
         # written to $DEVFLOW_REPORT_DIR is read as the check's evidence.\n\
         set -e\n\
         cd \"$(dirname \"$0\")/{up}\"\n\
         DEVFLOW_REPORT_DIR=\"${{DEVFLOW_REPORT_DIR:-{dir}/runs/local}}\"\n\
         export DEVFLOW_REPORT_DIR\n\
         mkdir -p \"$DEVFLOW_REPORT_DIR\"\n\
         {command}\n",
        name = script.name,
        command = script.command,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// devpit's to write over.
    Ours,
    /// Written when absent; a copy the person changed is theirs.
    Theirs,
    /// The `.gitignore`: the line added to what is there.
    Ignore,
    /// A check script no check runs any more: removed when devpit wrote it
    /// and nobody changed it, else said and left.
    Unused,
}

/// One file a setup writes, relative to the project's root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planned {
    pub path: String,
    text: String,
    kind: Kind,
    executable: bool,
}

/// What writing a planned file does, or did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileChange {
    pub path: String,
    /// `create`, `replace`, `same`, `kept` (a copy of the person's), `append`,
    /// `remove` (a script devpit wrote that no check runs) or `unused` (one
    /// the person changed, left for them).
    pub change: &'static str,
}

/// Every file a setup of `yaml` with `scripts` writes, and the Playwright
/// config when the project runs Playwright.
pub fn planned(yaml: &str, scripts: &[Script], playwright: Option<&str>) -> Vec<Planned> {
    planned_in(&Layout::default(), yaml, scripts, playwright)
}

/// [`planned`] in `layout`.
pub fn planned_in(
    layout: &Layout,
    yaml: &str,
    scripts: &[Script],
    playwright: Option<&str>,
) -> Vec<Planned> {
    let dir = layout.dir;
    let at = |path: String, text: String, kind: Kind, executable: bool| Planned {
        path,
        text,
        kind,
        executable,
    };
    let mut files = vec![
        at(layout.file.clone(), yaml.to_owned(), Kind::Ours, false),
        at(
            format!("{dir}/.gitignore"),
            format!("# A check run by hand reports under runs/local.\n{IGNORED}\n"),
            Kind::Ignore,
            false,
        ),
    ];
    files.extend(scripts_planned(dir, scripts));
    files.extend(playwright.map(|text| {
        at(
            crate::playwright::file_in(dir),
            text.to_owned(),
            Kind::Theirs,
            false,
        )
    }));
    files
}

/// devflow.yaml, and the scripts of the checks a change to one field added.
pub fn config_only(yaml: &str, scripts: &[Script]) -> Vec<Planned> {
    config_only_in(&Layout::default(), yaml, scripts)
}

/// [`config_only`] in `layout`.
pub fn config_only_in(layout: &Layout, yaml: &str, scripts: &[Script]) -> Vec<Planned> {
    let mut files: Vec<Planned> = planned_in(layout, yaml, &[], None)
        .into_iter()
        .take(1)
        .collect();
    files.extend(scripts_planned(layout.dir, scripts));
    files
}

fn scripts_planned<'a>(dir: &'a str, scripts: &'a [Script]) -> impl Iterator<Item = Planned> + 'a {
    scripts.iter().map(move |script| Planned {
        path: format!("{dir}/scripts/{}", script_file(&script.name)),
        text: script_text(dir, script),
        kind: Kind::Ours,
        executable: true,
    })
}

fn script_file(name: &str) -> String {
    format!("check-{name}.sh")
}

/// `files`, and each check script under `scripts/` that `config` no longer
/// runs: the setup says so, and removes the one devpit wrote as it was.
pub fn with_unused(root: &Path, config: &Config, files: Vec<Planned>) -> Vec<Planned> {
    let mut files = files;
    let dir = crate::folder::dir(root);
    let Ok(folder) = crate::fsguard::resolve(root, &format!("{dir}/scripts")) else {
        return files;
    };
    let Ok(entries) = std::fs::read_dir(folder) else {
        return files;
    };
    // A link is not devpit's script, whatever it points at.
    let mut unused: Vec<Planned> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|file| {
            let name = file.strip_prefix("check-")?.strip_suffix(".sh")?.to_owned();
            let path = format!("{dir}/scripts/{file}");
            let run = config
                .stages
                .execution
                .checks
                .iter()
                .any(|check| check.run.contains(&format!("scripts/{file}")));
            let planned = files.iter().any(|one| one.path == path);
            (!run && !planned).then_some(Planned {
                path,
                text: name,
                kind: Kind::Unused,
                executable: false,
            })
        })
        .collect();
    unused.sort_by(|a, b| a.path.cmp(&b.path));
    files.extend(unused);
    files
}

/// Whether `text` is the script devpit writes for check `name`, unchanged:
/// written again from the command and source it names, it is the same. A
/// command of more than one line was the person's to grow, so it is theirs.
fn generated(dir: &str, name: &str, text: &str) -> bool {
    let Some((head, command)) = text.split_once("mkdir -p \"$DEVFLOW_REPORT_DIR\"\n") else {
        return false;
    };
    if command.trim_end_matches('\n').contains('\n') {
        return false;
    }
    let source = head
        .lines()
        .nth(1)
        .and_then(|line| line.strip_prefix(&format!("# Devflow check `{name}`, found in ")))
        .and_then(|rest| rest.strip_suffix('.'));
    let script = Script {
        name: name.to_owned(),
        command: command.strip_suffix('\n').unwrap_or(command).to_owned(),
        source: source.map(str::to_owned),
    };
    script_text(dir, &script) == text
}

/// What writing `files` under `root` would do; nothing is written.
pub fn preview(root: &Path, files: &[Planned]) -> Vec<FileChange> {
    files
        .iter()
        .map(|file| FileChange {
            path: file.path.clone(),
            change: change_of(file, there(root, &file.path).as_deref()),
        })
        .collect()
}

/// Writes `files` under `root`, every folder and file resolved through
/// symlinks and kept inside the project. Commits nothing.
pub fn write(root: &Path, files: &[Planned]) -> Result<Vec<FileChange>, String> {
    let mut done = Vec::new();
    for file in files {
        let existing = there(root, &file.path);
        let change = change_of(file, existing.as_deref());
        let text = match (change, file.kind) {
            ("same" | "kept" | "unused", _) => {
                done.push(FileChange {
                    path: file.path.clone(),
                    change,
                });
                continue;
            }
            ("remove", _) => {
                removed(root, &file.path)?;
                done.push(FileChange {
                    path: file.path.clone(),
                    change,
                });
                continue;
            }
            ("append", Kind::Ignore) => {
                let mut kept = existing.unwrap_or_default();
                if !kept.ends_with('\n') {
                    kept.push('\n');
                }
                kept.push_str(IGNORED);
                kept.push('\n');
                kept
            }
            _ => file.text.clone(),
        };
        let parent = file.path.rsplit_once('/').map_or("", |(parent, _)| parent);
        folders(root, parent)?;
        let target = crate::fsguard::resolve_new(root, &file.path)
            .map_err(|err| format!("{}: {err}", file.path))?;
        std::fs::write(&target, text).map_err(|err| format!("{}: {err}", file.path))?;
        if file.executable {
            executable(&target);
        }
        done.push(FileChange {
            path: file.path.clone(),
            change,
        });
    }
    Ok(done)
}

/// Removes the file at `path`, itself and never what a link points at,
/// inside a folder of the project.
fn removed(root: &Path, path: &str) -> Result<(), String> {
    let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
    let folder = crate::fsguard::resolve(root, parent).map_err(|err| format!("{path}: {err}"))?;
    let entry = folder.join(name);
    if !std::fs::symlink_metadata(&entry).is_ok_and(|meta| meta.is_file()) {
        return Err(format!("{path} is not a file devflow wrote"));
    }
    std::fs::remove_file(entry).map_err(|err| format!("{path}: {err}"))
}

/// The file's text, when it is there and inside the project.
fn there(root: &Path, path: &str) -> Option<String> {
    let resolved = crate::fsguard::resolve(root, path).ok()?;
    let meta = std::fs::metadata(&resolved).ok()?;
    (meta.is_file() && meta.len() <= crate::folder::MOST_BYTES)
        .then(|| std::fs::read_to_string(resolved).ok())
        .flatten()
}

/// The folder a script at `path`, `<dir>/scripts/<file>`, belongs to.
fn script_dir(path: &str) -> &str {
    path.rsplit_once("/scripts/").map_or(DIR, |(dir, _)| dir)
}

fn change_of(file: &Planned, existing: Option<&str>) -> &'static str {
    match (existing, file.kind) {
        // The text of an unused script's plan is its check's name.
        (Some(text), Kind::Unused) if generated(script_dir(&file.path), &file.text, text) => {
            "remove"
        }
        (_, Kind::Unused) => "unused",
        (None, _) => "create",
        (Some(text), Kind::Ignore) => {
            if text.lines().any(|line| line.trim() == IGNORED) {
                "same"
            } else {
                "append"
            }
        }
        (Some(text), _) if text == file.text => "same",
        (Some(_), Kind::Theirs) => "kept",
        (Some(_), _) => "replace",
    }
}

/// Makes each folder of `relative` that is missing, refusing one that
/// leads outside the project.
pub(crate) fn folders(root: &Path, relative: &str) -> Result<(), String> {
    let mut walked = String::new();
    for part in relative.split('/').filter(|part| !part.is_empty()) {
        if !walked.is_empty() {
            walked.push('/');
        }
        walked.push_str(part);
        let folder =
            crate::fsguard::resolve_new(root, &walked).map_err(|err| format!("{walked}: {err}"))?;
        if !folder.is_dir() {
            std::fs::create_dir(&folder).map_err(|err| format!("{walked}: {err}"))?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
}

#[cfg(not(unix))]
fn executable(_: &Path) {}

#[cfg(test)]
#[path = "setup_tests.rs"]
mod tests;
