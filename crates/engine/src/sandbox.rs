//! The engine's sandbox for an exploit test: a throwaway worktree of the
//! commit, the project's dependencies linked in read-only, and the test run
//! in bwrap with a network namespace of its own (loopback alone) or in
//! docker with no network, under time, CPU and memory limits and `nice`.
//! The checkout is never written; a cloud's metadata service and every host
//! outside are unreachable, as is any third party.

use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::config::SandboxChoice;

/// Folders of installed dependencies a worktree lacks, linked in from the
/// checkout, read-only.
pub const DEPENDENCIES: [&str; 6] = [
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    ".bundle",
    "bower_components",
];
/// The variable the exploit's path reaches the test command through.
pub const EXPLOIT: &str = "DEVFLOW_EXPLOIT";
/// The variable the exploit test's name reaches it through.
pub const EXPLOIT_TEST: &str = "DEVFLOW_EXPLOIT_TEST";
/// The most of a run's output kept, from its end.
const TAIL: usize = 4_000;
/// The variables a test keeps from the engine's environment; anything else,
/// a secret above all, stays out.
const KEPT: [&str; 4] = ["PATH", "LANG", "LC_ALL", "TERM"];

/// Which sandbox it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Bwrap,
    Docker,
}

impl Kind {
    pub fn word(self) -> &'static str {
        match self {
            Kind::Bwrap => "bwrap",
            Kind::Docker => "docker",
        }
    }
}

/// A sandbox found on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sandbox {
    pub kind: Kind,
    pub program: PathBuf,
    /// Docker's image.
    pub image: Option<String>,
    /// `prlimit`, when this machine has it: bwrap's CPU and memory limits.
    pub prlimit: Option<PathBuf>,
}

/// What one test run may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub time: Duration,
    pub memory_mb: u64,
    pub cpus: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            time: Duration::from_secs(10 * 60),
            memory_mb: 4096,
            cpus: 2,
        }
    }
}

/// How a run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The test passed: exit 0.
    Green,
    /// It failed: any other exit.
    Red,
    /// It ran past its time and was stopped.
    TimedOut,
    /// It could not start, and why.
    Failed(String),
}

/// One run in the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ran {
    pub outcome: Outcome,
    pub exit: Option<i32>,
    /// The end of what it printed.
    pub tail: String,
    pub duration_ms: u64,
}

/// The sandbox `choice` asks for, found on `path`, or why there is none.
pub fn found(choice: SandboxChoice, image: Option<&str>, path: &OsStr) -> Result<Sandbox, String> {
    let on_path = |name: &str| crate::env::found_on(path, OsStr::new(name));
    let prlimit = on_path("prlimit");
    let bwrap = || -> Result<Sandbox, String> {
        if !cfg!(target_os = "linux") {
            return Err("bwrap runs on Linux only".to_owned());
        }
        let program = on_path("bwrap").ok_or("bwrap is not installed")?;
        // Unprivileged user namespaces may be off: it is then of no use.
        let works = Command::new(&program)
            .args([
                "--ro-bind",
                "/",
                "/",
                "--unshare-net",
                "--dev",
                "/dev",
                "true",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        if !works {
            return Err("bwrap cannot make a network namespace here".to_owned());
        }
        Ok(Sandbox {
            kind: Kind::Bwrap,
            program,
            image: None,
            prlimit: prlimit.clone(),
        })
    };
    let docker = || -> Result<Sandbox, String> {
        let image = image
            .filter(|image| !image.trim().is_empty())
            .ok_or("docker needs stages.attack.image, the image the tests run in")?;
        let program = on_path("docker").ok_or("docker is not installed")?;
        Ok(Sandbox {
            kind: Kind::Docker,
            program,
            image: Some(image.to_owned()),
            prlimit: None,
        })
    };
    match choice {
        SandboxChoice::Off => Err("stages.attack.sandbox is off".to_owned()),
        SandboxChoice::Bwrap => bwrap(),
        SandboxChoice::Docker => docker(),
        SandboxChoice::Auto => bwrap().or_else(|bwrap_not| {
            docker().map_err(|docker_not| format!("no sandbox here: {bwrap_not}; {docker_not}"))
        }),
    }
}

/// The dependency folders of `checkout` a worktree of it lacks: each
/// [`DEPENDENCIES`] folder that is there and is not a link.
pub fn dependencies(checkout: &Path) -> Vec<PathBuf> {
    DEPENDENCIES
        .iter()
        .map(|name| checkout.join(name))
        .filter(|at| {
            std::fs::symlink_metadata(at).is_ok_and(|meta| meta.is_dir() && !meta.is_symlink())
        })
        .collect()
}

/// The program and arguments that run `command` in `tree` inside the
/// sandbox, `deps` mounted read-only where they are.
pub fn argv(
    sandbox: &Sandbox,
    tree: &Path,
    deps: &[PathBuf],
    command: &str,
    limits: Limits,
    name: &str,
) -> Vec<String> {
    let tree = tree.display().to_string();
    match sandbox.kind {
        Kind::Bwrap => {
            let mut argv = vec![
                sandbox.program.display().to_string(),
                "--die-with-parent".into(),
                "--new-session".into(),
                "--unshare-net".into(),
                "--unshare-pid".into(),
                "--unshare-ipc".into(),
                "--unshare-uts".into(),
                "--ro-bind".into(),
                "/".into(),
                "/".into(),
                "--dev".into(),
                "/dev".into(),
                "--proc".into(),
                "/proc".into(),
                "--tmpfs".into(),
                "/tmp".into(),
                "--bind".into(),
                tree.clone(),
                tree.clone(),
                "--chdir".into(),
                tree,
                "--".into(),
            ];
            if let Some(prlimit) = &sandbox.prlimit {
                argv.extend([
                    prlimit.display().to_string(),
                    format!("--cpu={}", limits.time.as_secs() * u64::from(limits.cpus)),
                    format!("--data={}", limits.memory_mb * 1024 * 1024),
                    "--".into(),
                ]);
            }
            argv.extend(["sh".into(), "-c".into(), command.to_owned()]);
            argv
        }
        Kind::Docker => {
            let mut argv = vec![
                sandbox.program.display().to_string(),
                "run".into(),
                "--rm".into(),
                "--init".into(),
                "--name".into(),
                name.to_owned(),
                "--network".into(),
                "none".into(),
                "--read-only".into(),
                "--tmpfs".into(),
                "/tmp".into(),
                "--cap-drop".into(),
                "ALL".into(),
                "--security-opt".into(),
                "no-new-privileges".into(),
                "--pids-limit".into(),
                "512".into(),
                "--memory".into(),
                format!("{}m", limits.memory_mb),
                "--cpus".into(),
                limits.cpus.to_string(),
                "-v".into(),
                format!("{tree}:{tree}"),
            ];
            for dep in deps {
                let dep = dep.display().to_string();
                argv.extend(["-v".into(), format!("{dep}:{dep}:ro")]);
            }
            for name in [EXPLOIT, EXPLOIT_TEST, "HOME"] {
                argv.extend(["-e".into(), name.to_owned()]);
            }
            argv.extend([
                "-w".into(),
                tree,
                sandbox.image.clone().unwrap_or_default(),
                "sh".into(),
                "-c".into(),
                command.to_owned(),
            ]);
            argv
        }
    }
}

/// A throwaway worktree of a commit, removed when dropped.
pub struct Tree {
    pub root: PathBuf,
    pub at: PathBuf,
}

impl Drop for Tree {
    fn drop(&mut self) {
        crate::git::remove_detached(&self.root, &self.at);
    }
}

/// A worktree of `commit` at `at`, with the checkout's dependency folders
/// linked in, removed when the returned [`Tree`] is dropped.
pub fn tree_at(checkout: &Path, commit: &str, at: &Path) -> Result<Tree, String> {
    if let Some(parent) = at.parent() {
        std::fs::create_dir_all(parent).map_err(|err| format!("{}: {err}", parent.display()))?;
    }
    crate::git::add_detached(checkout, at, commit).map_err(|err| err.to_string())?;
    let tree = Tree {
        root: checkout.to_path_buf(),
        at: at.to_path_buf(),
    };
    for dep in dependencies(checkout) {
        let Some(name) = dep.file_name() else {
            continue;
        };
        let link = at.join(name);
        if std::fs::symlink_metadata(&link).is_err() {
            #[cfg(unix)]
            std::os::unix::fs::symlink(&dep, &link)
                .map_err(|err| format!("{}: {err}", link.display()))?;
        }
    }
    Ok(tree)
}

/// Writes an exploit at `relative` inside `tree`, refusing a place a link
/// takes out of it.
pub fn place(tree: &Path, relative: &str, code: &str) -> Result<PathBuf, String> {
    let relative = crate::attack::exploit_path(relative)?;
    let out = || format!("`{relative}` leads out of the worktree");
    let root = tree
        .canonicalize()
        .map_err(|err| format!("{}: {err}", tree.display()))?;
    let at = tree.join(&relative);
    if std::fs::symlink_metadata(&at).is_ok() {
        return Err(format!(
            "`{relative}` is a file the project has: an exploit is a new file"
        ));
    }
    let parent = at.parent().ok_or("an exploit has a folder")?;
    // Before anything is made: the part that is there stays inside.
    let there = parent
        .ancestors()
        .find(|one| one.exists())
        .and_then(|one| one.canonicalize().ok())
        .ok_or_else(out)?;
    if !there.starts_with(&root) {
        return Err(out());
    }
    std::fs::create_dir_all(parent).map_err(|err| format!("{}: {err}", parent.display()))?;
    if !parent
        .canonicalize()
        .is_ok_and(|parent| parent.starts_with(&root))
    {
        return Err(out());
    }
    std::fs::write(&at, code).map_err(|err| format!("{}: {err}", at.display()))?;
    Ok(at)
}

/// Runs `command` in `tree` inside `sandbox`: the exploit's path and name
/// reach it only through [`EXPLOIT`] and [`EXPLOIT_TEST`].
pub fn run(
    sandbox: &Sandbox,
    tree: &Path,
    command: &str,
    exploit: (&str, &str),
    limits: Limits,
) -> Ran {
    let began = Instant::now();
    let deps = dependencies(tree)
        .into_iter()
        .chain(
            DEPENDENCIES
                .iter()
                .filter_map(|name| std::fs::read_link(tree.join(name)).ok()),
        )
        .collect::<Vec<_>>();
    let name = format!(
        "devflow-exploit-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos())
    );
    let mut argv = argv(sandbox, tree, &deps, command, limits, &name);
    // Below the person's own work on this machine.
    let path = std::env::var_os("PATH").unwrap_or_default();
    if let Some(nice) = crate::env::found_on(&path, OsStr::new("nice")) {
        let mut niced = vec![nice.display().to_string(), "-n".into(), "10".into()];
        niced.append(&mut argv);
        argv = niced;
    }
    let mut child = Command::new(&argv[0]);
    child.args(&argv[1..]).env_clear();
    for name in KEPT {
        if let Some(value) = std::env::var_os(name) {
            child.env(name, value);
        }
    }
    child
        .env("HOME", "/tmp")
        .env(EXPLOIT, exploit.0)
        .env(EXPLOIT_TEST, exploit.1)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // A session of its own: on a timeout its whole group is ended, and
    // nothing outside it.
    crate::runner::descendants::in_a_session_of_its_own(&mut child);
    let failed = |why: String| Ran {
        outcome: Outcome::Failed(why),
        exit: None,
        tail: String::new(),
        duration_ms: began.elapsed().as_millis() as u64,
    };
    let mut child = match child.spawn() {
        Ok(child) => child,
        Err(err) => return failed(format!("{}: {err}", argv[0])),
    };
    let output = child
        .stdout
        .take()
        .zip(child.stderr.take())
        .map(|(out, err)| {
            std::thread::spawn(move || {
                let mut said = Vec::new();
                let _ = out.take(1 << 22).read_to_end(&mut said);
                let mut more = Vec::new();
                let _ = err.take(1 << 22).read_to_end(&mut more);
                said.extend(more);
                said
            })
        });
    let deadline = began + limits.time;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() >= deadline => {
                // The whole group: a test may have spawned its own.
                crate::runner::descendants::end_it_all(&mut child);
                let _ = child.wait();
                if sandbox.kind == Kind::Docker {
                    // The client gone, the container would run on.
                    let _ = Command::new(&sandbox.program)
                        .args(["kill", &name])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(err) => return failed(err.to_string()),
        }
    };
    let said = output
        .and_then(|reading| reading.join().ok())
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default();
    let tail: String = {
        let chars: Vec<char> = said.chars().collect();
        chars[chars.len().saturating_sub(TAIL)..].iter().collect()
    };
    let (outcome, exit) = match status {
        None => (Outcome::TimedOut, None),
        Some(status) if status.success() => (Outcome::Green, status.code()),
        Some(status) => (Outcome::Red, status.code()),
    };
    Ran {
        outcome,
        exit,
        tail,
        duration_ms: began.elapsed().as_millis() as u64,
    }
}

#[cfg(test)]
#[path = "sandbox_tests.rs"]
mod tests;
