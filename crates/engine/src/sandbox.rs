//! The engine's sandbox for an exploit test: a throwaway worktree of the
//! commit, the project's dependencies mounted in read-only where it keeps
//! them, its language's caches read-only (cargo's registry, Go's modules)
//! with the toolchain held offline, a Python venv made over the project's
//! own (its editable installs leading to the worktree), a Rust project's
//! one build of HEAD per attack copied in, and the test run in bwrap with a network namespace of its own (loopback alone) or in
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
/// Never `.bundle`: Bundler keeps its credentials there.
pub const DEPENDENCIES: [&str; 5] = [
    "node_modules",
    "vendor",
    ".venv",
    "venv",
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

/// Whether `image` names a docker image and nothing else: it goes into
/// `docker run` before the command, so a word that reads as a flag
/// (`--network=host`) or holds a space would set docker's own options.
pub fn image_named(image: &str) -> bool {
    let mut chars = image.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric())
        && chars.all(|one| one.is_ascii_alphanumeric() || "._/:@-".contains(one))
}

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
    /// Docker's: the internal network of a stack the exploit reaches; none
    /// when not said.
    pub network: Option<String>,
    /// What the exploit is told besides its path and test: the stack's
    /// targets.
    pub env: Vec<(String, String)>,
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
    /// Whether all it printed, not only its end, names the exploit's test
    /// with no harness error ([`crate::attack::reached`]): a red run that
    /// does reached its assertion.
    pub reached: bool,
    /// Whether all it printed says no test ran ([`crate::attack::none_ran`]):
    /// a green run that does refutes nothing.
    pub none_ran: bool,
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
            return Err(match userns_restricted() {
                true => "bwrap cannot make a network namespace here: unprivileged user namespaces \
                         are restricted (kernel.apparmor_restrict_unprivileged_userns=1)"
                    .to_owned(),
                false => "bwrap cannot make a network namespace here".to_owned(),
            });
        }
        Ok(Sandbox {
            kind: Kind::Bwrap,
            program,
            image: None,
            prlimit: prlimit.clone(),
            network: None,
            env: Vec::new(),
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
            network: None,
            env: Vec::new(),
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

/// A folder of this machine a run sees, read-only, at `to`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub from: PathBuf,
    pub to: PathBuf,
}

/// What a run sees of this machine besides its worktree: the dependency
/// folders, read-only, where the project keeps them in the worktree; its
/// language's caches, read-only, and the variables that point the toolchain
/// at them and keep it offline; under bwrap, the home folder that is
/// hidden, with the toolchains under it shown again read-only; and the
/// lines run before the test command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Seen {
    pub deps: Vec<Mount>,
    pub home: Option<PathBuf>,
    pub tools: Vec<PathBuf>,
    pub caches: Vec<Mount>,
    /// Folders made empty and writable for the run, before the caches
    /// mounted into them: a toolchain's home, its lock and build cache.
    pub writable: Vec<PathBuf>,
    pub env: Vec<(String, String)>,
    pub prelude: Option<String>,
}

/// The toolchains the test command reaches through `path` that live under
/// `home`, each shown read-only: a `PATH` folder, or its parent when that
/// holds the toolchain's `lib` (a node install); for `~/.cargo/bin`,
/// `~/.rustup` too, never `~/.cargo`'s credentials.
pub fn tools(home: &Path, path: &OsStr) -> Vec<PathBuf> {
    let mut tools: Vec<PathBuf> = Vec::new();
    let mut add = |at: PathBuf| {
        if at.is_dir() && at != home && !tools.contains(&at) {
            tools.push(at);
        }
    };
    for entry in std::env::split_paths(path).filter(|entry| entry.starts_with(home)) {
        let parent = entry.parent().map(Path::to_path_buf);
        match parent {
            Some(parent) if parent == home.join(".cargo") => {
                add(entry.clone());
                add(home.join(".rustup"));
            }
            Some(parent) if parent != home.join(".local") && parent.join("lib").is_dir() => {
                add(parent)
            }
            _ => add(entry),
        }
    }
    tools
}

/// Where a run sees cargo's registry and git checkouts, read-only, as its
/// `CARGO_HOME`: never the person's credentials or configuration.
pub const CARGO_HOME: &str = "/tmp/devflow-cargo";
/// Where a run sees Go's module cache, read-only, and keeps its build cache.
pub const GO_HOME: &str = "/tmp/devflow-go";
/// Where a run's Python venv is made over the project's own.
pub const PYTHON_HOME: &str = "/tmp/devflow-python";
/// Where a Rust run sees its attack's warm build, read-only: copied into
/// its own `target` before its test, so only its own code is compiled.
pub const CARGO_WARM: &str = "/tmp/devflow-cargo-warm";
/// What builds a Rust project's tests, its dependencies first, and runs none.
const CARGO_WARM_UP: &str = "cargo test --offline --no-run";
/// What runs a Python command in the project's venv: the sandbox makes that
/// venv the one `python` runs, offline, so it is dropped.
const PYTHON_RUNNERS: [&str; 3] = ["uv run ", "poetry run ", "pipenv run "];

/// What a project's language needs in the sandbox beyond its dependency
/// folders.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Language {
    pub caches: Vec<Mount>,
    pub writable: Vec<PathBuf>,
    pub env: Vec<(String, String)>,
    pub prelude: Option<String>,
    /// Under bwrap, folders under the home to show again: a toolchain the
    /// language needs that `PATH` does not name.
    pub tools: Vec<PathBuf>,
}

/// An environment variable of the engine's that names an absolute path.
fn absolute_var(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|at| at.is_absolute())
}

/// What the project in `tree` needs of its language, for `kind`, `home`
/// and `path` being the engine's: Rust's registry and Go's module cache
/// read-only, each toolchain kept offline; a Python venv made the one
/// `python` runs, with the project's own packages.
pub fn language(tree: &Tree, kind: Kind, home: Option<&Path>, path: &OsStr) -> Language {
    language_with(tree, kind, home, path, &absolute_var)
}

/// [`language`], the engine's variables read through `var`.
fn language_with(
    tree: &Tree,
    kind: Kind,
    home: Option<&Path>,
    path: &OsStr,
    var: &dyn Fn(&str) -> Option<PathBuf>,
) -> Language {
    let mut out = Language::default();
    let set = |out: &mut Language, name: &str, value: String| {
        out.env.push((name.to_owned(), value));
    };
    if tree.at.join("Cargo.toml").is_file() {
        let cargo = var("CARGO_HOME").or_else(|| home.map(|home| home.join(".cargo")));
        for part in ["registry", "git"] {
            if let Some(from) = cargo.as_ref().map(|cargo| cargo.join(part)) {
                if from.is_dir() {
                    out.caches.push(Mount {
                        from,
                        to: Path::new(CARGO_HOME).join(part),
                    });
                }
            }
        }
        out.writable.push(PathBuf::from(CARGO_HOME));
        set(&mut out, "CARGO_HOME", CARGO_HOME.to_owned());
        set(&mut out, "CARGO_NET_OFFLINE", "true".to_owned());
        // Docker's image brings its own toolchain; bwrap shows the person's.
        if kind == Kind::Bwrap {
            let rustup = var("RUSTUP_HOME")
                .or_else(|| home.map(|home| home.join(".rustup")))
                .filter(|at| at.is_dir());
            if let Some(rustup) = rustup {
                set(&mut out, "RUSTUP_HOME", rustup.display().to_string());
                out.tools.push(rustup);
            }
        }
    }
    if tree.at.join("go.mod").is_file() {
        let go = Path::new(GO_HOME);
        out.writable.push(go.to_path_buf());
        if let Some(from) = go_mod_cache(home, path, var).filter(|at| at.is_dir()) {
            out.caches.push(Mount {
                from,
                to: go.join("mod"),
            });
            set(&mut out, "GOMODCACHE", go.join("mod").display().to_string());
        }
        set(&mut out, "GOCACHE", go.join("cache").display().to_string());
        set(&mut out, "GOTMPDIR", go.display().to_string());
        set(&mut out, "GOPROXY", "off".to_owned());
        set(&mut out, "GOTOOLCHAIN", "local".to_owned());
        set(&mut out, "GOFLAGS", "-buildvcs=false".to_owned());
    }
    if let Some(venv) = tree.deps.iter().find(|dep| venv(&dep.from)) {
        if let Some(version) = python_version(&venv.from) {
            let base = venv_base(&venv.from);
            if kind == Kind::Bwrap {
                // A Python uv or pyenv installed under the home: its own
                // install, holding its standard library, never `~/.local`
                // whole (the person's other files are there).
                let install = base.as_deref().and_then(Path::parent);
                if let (Some(install), Some(home)) = (install, home) {
                    if install.starts_with(home)
                        && install != home
                        && !home.join(".local").starts_with(install)
                        && install != home.join(".local")
                        && install.join("lib").join(&version).is_dir()
                    {
                        out.tools.push(install.to_path_buf());
                    }
                }
            }
            // Where an editable install may point: the checkout, the main
            // worktree whose venv a linked one runs, or the folder a
            // project's own `.venv` is in; never the folder poetry or
            // pipenv keep their venvs in.
            let own = venv
                .from
                .file_name()
                .is_some_and(|name| name == ".venv" || name == "venv");
            let mut roots: Vec<PathBuf> = [venv.from.parent().filter(|_| own)]
                .into_iter()
                .flatten()
                .map(Path::to_path_buf)
                .chain([tree.root.clone()])
                .chain(main_worktree(&tree.root))
                .collect();
            for root in roots.clone() {
                if let Ok(real) = root.canonicalize() {
                    if !roots.contains(&real) {
                        roots.push(real);
                    }
                }
            }
            let editable = editable(&venv.from, &version, &roots, &tree.at);
            out.prelude = Some(python_prelude(
                Path::new(PYTHON_HOME),
                &venv.to,
                &version,
                base.as_deref(),
                &editable,
            ));
        }
    }
    out
}

/// The command a run gives the shell: a Python runner before it dropped
/// once the sandbox made the venv the one `python` runs.
pub fn unwrapped<'a>(command: &'a str, language: &Language) -> &'a str {
    if language.prelude.is_none() {
        return command;
    }
    let trimmed = command.trim_start();
    PYTHON_RUNNERS
        .iter()
        .find_map(|runner| trimmed.strip_prefix(runner))
        .unwrap_or(command)
}

/// Go's module cache on this machine, as `go env` says it or, without go,
/// as its variables and default do.
fn go_mod_cache(
    home: Option<&Path>,
    path: &OsStr,
    var: &dyn Fn(&str) -> Option<PathBuf>,
) -> Option<PathBuf> {
    let said = crate::env::found_on(path, OsStr::new("go")).and_then(|go| {
        // Out of any module, its toolchain line never fetches another.
        asked(
            &go,
            &["env", "GOMODCACHE"],
            Path::new("/"),
            &[("GOTOOLCHAIN", "local")],
        )
    });
    said.map(PathBuf::from)
        .filter(|at| at.is_absolute())
        .or_else(|| var("GOMODCACHE"))
        .or_else(|| {
            var("GOPATH")
                .and_then(|all| std::env::split_paths(&all).next())
                .filter(|at| at.is_absolute())
                .map(|at| at.join("pkg/mod"))
        })
        .or_else(|| home.map(|home| home.join("go/pkg/mod")))
}

/// Whether `dir` is a Python venv.
fn venv(dir: &Path) -> bool {
    dir.join("pyvenv.cfg").is_file()
}

/// The `pythonX.Y` a venv was made with, as its `lib` folder names it.
fn python_version(venv: &Path) -> Option<String> {
    let mut found: Vec<String> = std::fs::read_dir(venv.join("lib"))
        .ok()?
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| {
            name.strip_prefix("python3.").is_some_and(|minor| {
                !minor.is_empty() && minor.chars().all(|one| one.is_ascii_digit())
            })
        })
        .collect();
    found.sort();
    found.into_iter().next()
}

/// The folder of the interpreter a venv was made from: its `pyvenv.cfg`'s
/// `home`.
fn venv_base(venv: &Path) -> Option<PathBuf> {
    let said = std::fs::read_to_string(venv.join("pyvenv.cfg")).ok()?;
    said.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key.trim() == "home")
            .then(|| PathBuf::from(value.trim()))
            .filter(|at| at.is_absolute())
    })
}

/// What an editable install of the project in a venv says of the checkout,
/// said again of the worktree: the paths its `.pth` files add, and the
/// modules they import that name it (setuptools' finder, whose `MAPPING`
/// leads each package to its folder). The run imports the worktree's code,
/// never the checkout's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Editable {
    paths: Vec<String>,
    /// Each module's name and its text, the checkout's paths in it now the
    /// worktree's.
    modules: Vec<(String, String)>,
}

/// The most of a `.pth` or a module it imports read: setuptools writes a
/// few kilobytes.
const MOST_EDITABLE: u64 = 64 * 1024;
/// The most modules a venv's `.pth` files import that are said again, and
/// the most of their text in all: it goes into the one argument `sh -c`
/// runs, which Linux holds to 128 KiB.
const MOST_MODULES: usize = 32;
const MOST_MODULES_TEXT: usize = 64 * 1024;

/// A small regular file's text, never through a link.
fn small_text(at: &Path) -> Option<String> {
    let meta = std::fs::symlink_metadata(at).ok()?;
    (meta.is_file() && meta.len() <= MOST_EDITABLE)
        .then(|| std::fs::read_to_string(at).ok())
        .flatten()
}

/// Whether `name` is a module's plain name: no dots, no path.
fn module_name(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 200
        && chars
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|one| one.is_ascii_alphanumeric() || one == '_')
}

/// The modules a `.pth` line imports: Python runs a line that begins with
/// `import`, and each of its `import` statements names them.
fn imported(line: &str) -> Vec<&str> {
    line.split(';')
        .filter_map(|part| part.trim().strip_prefix("import "))
        .flat_map(|names| names.split(','))
        .filter_map(|name| name.split_whitespace().next())
        .filter(|name| module_name(name))
        .collect()
}

/// `text` with each path under one of `roots` it quotes said under `tree`
/// instead, the deepest root first; `None` when it quotes none.
fn requoted(text: &str, roots: &[PathBuf], tree: &Path) -> Option<String> {
    let tree = tree.display().to_string();
    let mut out = text.to_owned();
    for root in roots
        .iter()
        .filter(|root| root.is_absolute() && root.parent().is_some())
    {
        let root = root.display().to_string();
        // Python would have escaped it: such a path is never matched.
        if root.contains(['\'', '"', '\\']) {
            continue;
        }
        for quote in ['\'', '"'] {
            out = out
                .replace(&format!("{quote}{root}/"), &format!("{quote}{tree}/"))
                .replace(
                    &format!("{quote}{root}{quote}"),
                    &format!("{quote}{tree}{quote}"),
                );
        }
    }
    (out != text).then_some(out)
}

/// What a venv's editable installs under one of `roots` say, said again
/// under `tree` ([`Editable`]).
fn editable(venv: &Path, version: &str, roots: &[PathBuf], tree: &Path) -> Editable {
    // The deepest first: a checkout inside the main worktree is its own.
    let mut roots = roots.to_vec();
    roots.sort_by_key(|root| std::cmp::Reverse(root.as_os_str().len()));
    let roots = roots.as_slice();
    let site = venv.join("lib").join(version).join("site-packages");
    let mut out = Editable::default();
    let Ok(entries) = std::fs::read_dir(&site) else {
        return out;
    };
    let mut pths: Vec<PathBuf> = entries
        .flatten()
        .take(2_000)
        .map(|entry| entry.path())
        .filter(|at| at.extension().is_some_and(|ext| ext == "pth"))
        .collect();
    pths.sort();
    for pth in pths {
        let Some(text) = small_text(&pth) else {
            continue;
        };
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with("import") {
                for name in imported(line) {
                    if out.modules.len() >= MOST_MODULES
                        || out.modules.iter().any(|(had, _)| had == name)
                    {
                        continue;
                    }
                    let module = small_text(&site.join(format!("{name}.py")))
                        .and_then(|text| requoted(&text, roots, tree));
                    let held: usize = out.modules.iter().map(|(_, text)| text.len()).sum();
                    if let Some(module) =
                        module.filter(|module| held + module.len() <= MOST_MODULES_TEXT)
                    {
                        out.modules.push((name.to_owned(), module));
                    }
                }
                continue;
            }
            let rest = roots
                .iter()
                .filter(|root| root.is_absolute() && root.parent().is_some())
                .find_map(|root| Path::new(line).strip_prefix(root).ok());
            if let Some(rest) = rest {
                let mapped = tree.join(rest).display().to_string();
                if !out.paths.contains(&mapped) {
                    out.paths.push(mapped);
                }
            }
        }
    }
    out.paths.sort();
    out
}

/// `text` as one word of `sh`.
fn quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// The lines that make a venv at `at` over the project's own (`venv`, as
/// the run sees it) the one `python` runs: its interpreter is the base the project
/// made it with when the sandbox has it, else the sandbox's `pythonX.Y` of
/// the same version; its packages are the project's, and an editable
/// install points at the worktree. Without that version, the run says so
/// and stops.
fn python_prelude(
    at: &Path,
    venv: &Path,
    version: &str,
    base: Option<&Path>,
    editable: &Editable,
) -> String {
    let site = venv.join("lib").join(version).join("site-packages");
    let site = serde_json::to_string(&site.display().to_string()).unwrap_or_default();
    // The worktree's code first: where the checkout is in sight, its own
    // editable path, which the venv's packages add, comes after.
    let mut lines: Vec<String> = editable.paths.iter().map(|one| quoted(one)).collect();
    lines.push(quoted(&format!("import site; site.addsitedir({site})")));
    // A module an editable `.pth` imports is found here first, ahead of the
    // venv's own: setuptools' finder then leads to the worktree.
    let modules: String = editable
        .modules
        .iter()
        .map(|(name, text)| {
            format!(
                "printf '%s' {} > {}/lib/{version}/site-packages/{name}.py\n",
                quoted(text),
                quoted(&at.display().to_string())
            )
        })
        .collect();
    let from_base = base
        .map(|base| quoted(&base.join(version).display().to_string()))
        .unwrap_or_default();
    let home = quoted(&at.display().to_string());
    format!(
        "devflow_py=\n\
         for one in {from_base} \"$(command -v {version})\"; do if [ -n \"$one\" ] && [ -x \"$one\" ]; then devflow_py=$one; break; fi; done\n\
         if [ -z \"$devflow_py\" ]; then echo 'devflow: the sandbox has no {version}, the Python the project venv was made with' >&2; exit 127; fi\n\
         mkdir -p {home}/bin {home}/lib/{version}/site-packages\n\
         for one in python python3 {version}; do ln -sf \"$devflow_py\" {home}/bin/$one; done\n\
         printf 'home = %s\\ninclude-system-site-packages = false\\n' \"${{devflow_py%/*}}\" > {home}/pyvenv.cfg\n\
         printf '%s\\n' {lines} > {home}/lib/{version}/site-packages/00-devflow.pth\n\
         {modules}\
         PATH={home}/bin:$PATH VIRTUAL_ENV={home}\n\
         export PATH VIRTUAL_ENV\n",
        lines = lines.join(" "),
    )
}

/// What `program` prints on its standard output, run in `cwd` with `env`
/// added, once it ends well within a while; `None` otherwise.
fn asked(program: &Path, args: &[&str], cwd: &Path, env: &[(&str, &str)]) -> Option<String> {
    let mut child = Command::new(program);
    child
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (name, value) in env {
        child.env(name, value);
    }
    let mut child = child.spawn().ok()?;
    let out = child.stdout.take().map(drained);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let said = out?.join().ok()?;
                return status
                    .success()
                    .then(|| String::from_utf8_lossy(&said).trim().to_owned())
                    .filter(|said| !said.is_empty());
            }
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => return None,
        }
    }
}

/// The venv a project's Python tool keeps out of its folder, when it has
/// none of its own: poetry's or pipenv's, asked of the tool in `roots` in
/// turn. Asking writes nothing.
fn venv_elsewhere(roots: &[PathBuf], path: &OsStr) -> Option<PathBuf> {
    let tool = |name: &str| crate::env::found_on(path, OsStr::new(name));
    roots.iter().find_map(|root| {
        let said = if root.join("poetry.lock").is_file() {
            tool("poetry").and_then(|poetry| asked(&poetry, &["env", "info", "--path"], root, &[]))
        } else if root.join("Pipfile").is_file() {
            tool("pipenv").and_then(|pipenv| asked(&pipenv, &["--venv"], root, &[]))
        } else {
            None
        };
        said.map(PathBuf::from)
            .filter(|at| at.is_absolute() && venv(at))
    })
}

/// The program and arguments that run `command` in `tree` inside the
/// sandbox, with what it may see.
pub fn argv(
    sandbox: &Sandbox,
    tree: &Path,
    seen: &Seen,
    command: &str,
    limits: Limits,
    name: &str,
) -> Vec<String> {
    let tree = tree.display().to_string();
    let shown = |at: &PathBuf| at.display().to_string();
    match sandbox.kind {
        Kind::Bwrap => {
            let mut argv: Vec<String> = [
                sandbox.program.display().to_string().as_str(),
                "--die-with-parent",
                "--new-session",
                "--unshare-net",
                "--unshare-pid",
                "--unshare-ipc",
                "--unshare-uts",
                "--ro-bind",
                "/",
                "/",
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "--tmpfs",
                "/tmp",
                // The host's sockets and the person's files stay out of reach.
                "--tmpfs",
                "/run",
            ]
            .iter()
            .map(|one| (*one).to_owned())
            .collect();
            if let Some(home) = &seen.home {
                argv.extend(["--tmpfs".into(), shown(home)]);
            }
            for at in &seen.tools {
                argv.extend(["--ro-bind".into(), shown(at), shown(at)]);
            }
            argv.extend(["--bind".into(), tree.clone(), tree.clone()]);
            for at in &seen.writable {
                argv.extend(["--tmpfs".into(), shown(at)]);
            }
            // Over the tree: its dependency folders, where the project keeps them.
            for mount in seen.deps.iter().chain(&seen.caches) {
                argv.extend(["--ro-bind".into(), shown(&mount.from), shown(&mount.to)]);
            }
            for (name, value) in &seen.env {
                argv.extend(["--setenv".into(), name.clone(), value.clone()]);
            }
            argv.extend(["--chdir".into(), tree, "--".into()]);
            if let Some(prlimit) = &sandbox.prlimit {
                argv.extend([
                    prlimit.display().to_string(),
                    format!("--cpu={}", limits.time.as_secs() * u64::from(limits.cpus)),
                    format!("--data={}", limits.memory_mb * 1024 * 1024),
                    "--".into(),
                ]);
            }
            argv.extend(["sh".into(), "-c".into(), with_prelude(seen, command)]);
            argv
        }
        Kind::Docker => {
            // SAFETY: plain syscalls.
            let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
            let mut argv: Vec<String> = vec![
                sandbox.program.display().to_string(),
                "run".into(),
                "--rm".into(),
                "--init".into(),
                "--name".into(),
                name.to_owned(),
                "--user".into(),
                format!("{uid}:{gid}"),
                "--network".into(),
                sandbox.network.clone().unwrap_or_else(|| "none".to_owned()),
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
            for at in &seen.writable {
                // Docker's tmpfs is noexec unless said: Go runs its test
                // binary from its work folder.
                argv.extend(["--tmpfs".into(), format!("{}:exec,mode=1777", shown(at))]);
            }
            for mount in seen.deps.iter().chain(&seen.caches) {
                argv.extend([
                    "-v".into(),
                    format!("{}:{}:ro", shown(&mount.from), shown(&mount.to)),
                ]);
            }
            for name in [EXPLOIT, EXPLOIT_TEST] {
                argv.extend(["-e".into(), name.to_owned()]);
            }
            for (name, value) in sandbox.env.iter().chain(&seen.env) {
                argv.extend(["-e".into(), format!("{name}={value}")]);
            }
            argv.extend([
                "-e".into(),
                "HOME=/tmp".into(),
                "-w".into(),
                tree,
                sandbox.image.clone().unwrap_or_default(),
                "sh".into(),
                "-c".into(),
                with_prelude(seen, command),
            ]);
            argv
        }
    }
}

/// `command` after the lines [`Seen`] runs before it.
fn with_prelude(seen: &Seen, command: &str) -> String {
    match &seen.prelude {
        Some(prelude) => format!("{prelude}{command}"),
        None => command.to_owned(),
    }
}

/// Whether AppArmor keeps unprivileged user namespaces from being made, as
/// Ubuntu does from 23.10: bwrap then cannot sandbox.
fn userns_restricted() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        .is_ok_and(|said| said.trim() == "1")
}

/// The dependency folders a run of `checkout` sees: its own, then those of
/// the repository's main worktree that it lacks. A detached tree an attack
/// reviews in has none of its own (`node_modules` is never committed), so
/// without the main worktree's an exploit test would fetch them, offline.
pub fn dependencies_for(checkout: &Path) -> Vec<PathBuf> {
    let mut found = dependencies(checkout);
    if let Some(main) = main_worktree(checkout) {
        for dep in dependencies(&main) {
            if !found.iter().any(|one| one.file_name() == dep.file_name()) {
                found.push(dep);
            }
        }
    }
    found
}

/// The repository's main worktree, when `checkout` is another.
fn main_worktree(checkout: &Path) -> Option<PathBuf> {
    let same = |a: &Path, b: &Path| match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    };
    crate::git::worktrees(checkout)
        .ok()
        .and_then(|all| all.into_iter().next())
        .map(PathBuf::from)
        .filter(|main| !same(main, checkout))
}

/// A throwaway worktree of a commit, removed when dropped, and the
/// checkout's dependency folders a run mounts into it.
pub struct Tree {
    pub root: PathBuf,
    pub at: PathBuf,
    pub deps: Vec<Mount>,
    /// A Rust run's warm build ([`warmed`]), the `target` it starts from.
    pub warm: Option<PathBuf>,
}

impl Drop for Tree {
    fn drop(&mut self) {
        crate::git::remove_detached(&self.root, &self.at);
    }
}

/// A worktree of `commit` at `at`, with the checkout's dependency folders
/// ([`dependencies_for`]) to mount where the project keeps them, removed
/// when the returned [`Tree`] is dropped. A project with no venv of its own
/// gets the one its poetry or pipenv keeps elsewhere, as `.venv`. Only the
/// folders found here are the run's dependencies: one the commit itself
/// holds is never mounted over. Each is mounted, not linked: a runner that
/// resolves a link would reach the checkout instead, which the run never
/// sees (PHP's autoloader finds the project's classes beside `vendor`).
pub fn tree_at(checkout: &Path, commit: &str, at: &Path) -> Result<Tree, String> {
    if let Some(parent) = at.parent() {
        std::fs::create_dir_all(parent).map_err(|err| format!("{}: {err}", parent.display()))?;
    }
    crate::git::add_detached(checkout, at, commit).map_err(|err| err.to_string())?;
    let mut tree = Tree {
        root: checkout.to_path_buf(),
        at: at.to_path_buf(),
        deps: Vec::new(),
        warm: None,
    };
    let mut wanted: Vec<(std::ffi::OsString, PathBuf)> = dependencies_for(checkout)
        .into_iter()
        .filter_map(|dep| Some((dep.file_name()?.to_owned(), dep)))
        .collect();
    if !wanted.iter().any(|(_, dep)| venv(dep)) {
        let mut roots = vec![checkout.to_path_buf()];
        roots.extend(main_worktree(checkout));
        let path = std::env::var_os("PATH").unwrap_or_default();
        if let Some(elsewhere) = venv_elsewhere(&roots, &path) {
            wanted.push((".venv".into(), elsewhere));
        }
    }
    for (name, from) in wanted {
        let to = at.join(&name);
        if std::fs::symlink_metadata(&to).is_err() {
            std::fs::create_dir(&to).map_err(|err| format!("{}: {err}", to.display()))?;
            tree.deps.push(Mount { from, to });
        }
    }
    Ok(tree)
}

/// A Rust run started from its attack's warm build ([`Tree::warm`]): that
/// build mounted read-only at [`CARGO_WARM`], and copied first as the
/// worktree's own `target`, or no `target` at all when the copy fails.
fn from_warm(language: &mut Language, tree: &Tree) {
    let Some(warm) = tree
        .warm
        .as_ref()
        .filter(|warm| warm.is_dir() && tree.at.join("Cargo.toml").is_file())
    else {
        return;
    };
    language.caches.push(Mount {
        from: warm.clone(),
        to: PathBuf::from(CARGO_WARM),
    });
    language.prelude = Some(format!(
        "if [ -d {CARGO_WARM} ] && [ ! -e target ]; then mkdir target && cp -a {CARGO_WARM}/. target/ 2>/dev/null || rm -rf target; fi\n{}",
        language.prelude.take().unwrap_or_default()
    ));
}

/// A Rust project's build in `tree`, made once for an attack's exploits:
/// its tests built offline in `sandbox` and none run, as each exploit's own
/// run would build them. The `target` it leaves, its dependencies above
/// all, even when the project's own code did not compile, is each exploit's
/// to start from ([`Tree::warm`]): mounted read-only and copied into its own
/// worktree, so nothing one exploit leaves reaches the next. `None` for a
/// project that is not Rust, or when nothing was built.
pub fn warmed(sandbox: &Sandbox, tree: &Tree, limits: Limits) -> Option<PathBuf> {
    if !tree.at.join("Cargo.toml").is_file() {
        return None;
    }
    let _ = run(sandbox, tree, CARGO_WARM_UP, ("", ""), limits);
    let target = tree.at.join("target");
    target.is_dir().then_some(target)
}

/// Writes an exploit at `relative` inside `tree` as a new file, refusing a
/// place a link takes out of it.
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

/// The docker client's own settings, kept for it alone: only the `-e`
/// list reaches the container.
const DOCKER_CLIENT: [&str; 5] = [
    "DOCKER_HOST",
    "DOCKER_CONFIG",
    "DOCKER_CONTEXT",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
];

fn drained(from: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut said = Vec::new();
        let _ = from.take(1 << 22).read_to_end(&mut said);
        said
    })
}

/// Runs `command` in `tree` inside `sandbox`: the exploit's path and name
/// reach it only through [`EXPLOIT`] and [`EXPLOIT_TEST`].
pub fn run(
    sandbox: &Sandbox,
    tree: &Tree,
    command: &str,
    exploit: (&str, &str),
    limits: Limits,
) -> Ran {
    let began = Instant::now();
    let path = std::env::var_os("PATH").unwrap_or_default();
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let mut language = language(tree, sandbox.kind, home.as_deref(), &path);
    let command = unwrapped(command, &language);
    from_warm(&mut language, tree);
    let mut seen = Seen {
        deps: tree.deps.clone(),
        tools: home
            .as_deref()
            .map_or_else(Vec::new, |home| tools(home, &path)),
        home: home
            .clone()
            .filter(|home| home.is_absolute() && home != Path::new("/")),
        caches: language.caches,
        writable: language.writable,
        env: language.env,
        prelude: language.prelude,
    };
    for tool in language.tools {
        if !seen.tools.contains(&tool) {
            seen.tools.push(tool);
        }
    }
    let name = format!(
        "devflow-exploit-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos())
    );
    let mut argv = argv(sandbox, &tree.at, &seen, command, limits, &name);
    // Below the person's own work on this machine.
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
    match sandbox.kind {
        Kind::Docker => {
            for name in DOCKER_CLIENT {
                if let Some(value) = std::env::var_os(name) {
                    child.env(name, value);
                }
            }
            if let Some(home) = &home {
                child.env("HOME", home);
            }
        }
        Kind::Bwrap => {
            child.env("HOME", "/tmp");
        }
    }
    child
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
        reached: false,
        none_ran: false,
        duration_ms: began.elapsed().as_millis() as u64,
    };
    let mut child = match child.spawn() {
        Ok(child) => child,
        Err(err) => return failed(format!("{}: {err}", argv[0])),
    };
    // Both read at once: a test that fills one pipe never waits on the other.
    let out = child.stdout.take().map(drained);
    let err = child.stderr.take().map(drained);
    let deadline = began + limits.time;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() >= deadline || crate::call::cancelled() => {
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
    let mut said = Vec::new();
    for reading in [out, err].into_iter().flatten() {
        said.extend(reading.join().unwrap_or_default());
    }
    let said = String::from_utf8_lossy(&said);
    let (tail, reached, none_ran) = judged(&said, exploit.1);
    let (outcome, exit) = match status {
        None => (Outcome::TimedOut, None),
        Some(status) if status.success() => (Outcome::Green, status.code()),
        Some(status) => (Outcome::Red, status.code()),
    };
    Ran {
        outcome,
        exit,
        tail,
        reached,
        none_ran,
        duration_ms: began.elapsed().as_millis() as u64,
    }
}

/// What a run printed, as its report keeps it (its end) and as it is judged
/// (all of it): whether it names `test`, and whether it says no test ran. A
/// runner prints the failing test's name first and its stack after, so the
/// end alone may not name it.
fn judged(said: &str, test: &str) -> (String, bool, bool) {
    let chars: Vec<char> = said.chars().collect();
    let tail = chars[chars.len().saturating_sub(TAIL)..].iter().collect();
    (
        tail,
        crate::attack::reached(said, test),
        crate::attack::none_ran(said),
    )
}

#[cfg(test)]
#[path = "sandbox_tests.rs"]
mod tests;
