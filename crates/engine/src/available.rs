//! Whether a detected command can run on this machine, before it is
//! recommended: its program found on the `PATH` devpit gives checks, or, for
//! `make X`, every program `make -n X` says it would start. A Makefile's
//! `lint` calling a phpstan nobody installed is a red check on every card.

use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use crate::detect::Detected;

/// How long `make -n` has to say what it would run.
const DRY_RUN: Duration = Duration::from_secs(5);
/// The most of `make -n`'s output read.
const MOST_OUTPUT: u64 = 256 * 1024;

/// Words a shell runs itself, so there is nothing on the `PATH` to find.
const BUILT_IN: &[&str] = &[
    ".", ":", "[", "[[", "!", "{", "}", "alias", "break", "case", "cd", "command", "continue",
    "do", "done", "echo", "elif", "else", "esac", "eval", "exec", "exit", "export", "false", "fi",
    "for", "if", "local", "printf", "pwd", "read", "return", "set", "shift", "source", "test",
    "then", "trap", "true", "type", "umask", "unset", "until", "wait", "while",
];

/// Marks each command in `detected` that cannot run with why.
pub fn validated(root: &Path, path: &OsStr, detected: &mut Detected) {
    let searched = searched(root, path);
    for found in detected.every_mut() {
        found.unavailable = why_not(root, &searched, &found.command);
    }
}

/// `path`, then the project's own `vendor/bin` and `node_modules/.bin`, where
/// Composer and npm put what a project's scripts call.
pub(crate) fn searched(root: &Path, path: &OsStr) -> OsString {
    let own = ["vendor/bin", "node_modules/.bin"]
        .iter()
        .map(|dir| root.join(dir));
    std::env::join_paths(std::env::split_paths(path).chain(own)).unwrap_or_else(|_| path.into())
}

/// Why `command` cannot run from `root` with `path`, or `None` when it can.
pub fn why_not(root: &Path, path: &OsStr, command: &str) -> Option<String> {
    let program = first_program(command)?;
    if !runs(root, path, program) {
        return Some(missing(program));
    }
    let target = make_target(command)?;
    let lines = match dry_run(root, path, program, target) {
        Ok(lines) => lines,
        Err(why) => return Some(format!("`make -n {target}` failed: {why}")),
    };
    lines
        .lines()
        .filter_map(first_program)
        .find(|program| !runs(root, path, program))
        .map(|program| format!("`make {target}` runs {}", missing(program)))
}

fn missing(program: &str) -> String {
    if program.contains('/') {
        format!("`{program}`, which is not in the project: install its dependencies")
    } else {
        format!("`{program}`, which is not installed or not on the PATH")
    }
}

/// The target of a bare `make X`, the only form whose recipe is read.
pub(crate) fn make_target(command: &str) -> Option<&str> {
    let mut words = command.split_whitespace();
    let (make, target) = (words.next()?, words.next()?);
    let plain = target
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte));
    (make == "make" && plain && !target.starts_with('-') && words.next().is_none())
        .then_some(target)
}

/// The program a shell line starts, when it can be told without running it:
/// past `NAME=value` assignments, and never a shell built-in or a word made
/// of variables and quotes. Make's own `make[1]:` lines name no program.
pub(crate) fn first_program(line: &str) -> Option<&str> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with("make[") {
        return None;
    }
    let word = line.split_whitespace().find(|word| !assignment(word))?;
    let opaque = word.contains(['$', '`', '"', '\'', '(', ')', '<', '>', '|', '&', ';', '*']);
    (!opaque && !BUILT_IN.contains(&word) && !word.ends_with(':')).then_some(word)
}

fn assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

/// Whether `program` runs: a path from the root to an executable file, or
/// a name on `path`.
fn runs(root: &Path, path: &OsStr, program: &str) -> bool {
    if program.contains('/') {
        let at = if Path::new(program).is_absolute() {
            PathBuf::from(program)
        } else {
            root.join(program)
        };
        return executable(&at);
    }
    crate::env::found_on(path, OsStr::new(program)).is_some()
}

#[cfg(unix)]
fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn executable(path: &Path) -> bool {
    path.is_file()
}

/// What `make -n target` prints, run from `root` with `path` and none of a
/// parent make's flags, or why it failed.
fn dry_run(root: &Path, path: &OsStr, make: &str, target: &str) -> Result<String, String> {
    let program = crate::env::found_on(path, OsStr::new(make)).ok_or_else(|| missing(make))?;
    let mut command = crate::env::command(program);
    command
        .arg("-n")
        .arg(target)
        .current_dir(root)
        .env("PATH", path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Run from a `make test`, the child would join its jobserver.
    for inherited in ["MAKEFLAGS", "MFLAGS", "MAKELEVEL", "MAKEOVERRIDES"] {
        command.env_remove(inherited);
    }
    let mut child = command.spawn().map_err(|err| err.to_string())?;
    let read = |stream: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut text = String::new();
            if let Some(stream) = stream {
                let _ = stream.take(MOST_OUTPUT).read_to_string(&mut text);
            }
            text
        })
    };
    let out = read(
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let err = read(
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < DRY_RUN => {
                std::thread::sleep(Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("it said nothing in {}s", DRY_RUN.as_secs()));
            }
        }
    };
    let out = out.join().unwrap_or_default();
    let err = err.join().unwrap_or_default();
    if status.success() {
        return Ok(out);
    }
    Err(err
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("it exited with an error")
        .trim()
        .to_owned())
}

#[cfg(test)]
#[path = "available_tests.rs"]
mod tests;
