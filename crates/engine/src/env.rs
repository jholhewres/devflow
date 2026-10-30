//! The programs devflow runs on the person's behalf, found where their shell
//! finds them.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

/// How a host that embeds the engine starts a program: devpit's finds it on
/// the login shell's `PATH` and takes its own AppImage out of the child.
pub type Spawner = fn(&OsStr) -> Command;

static SPAWNER: std::sync::OnceLock<Spawner> = std::sync::OnceLock::new();

/// Every program the engine starts from now on is started by `spawner`. Set
/// once, before the first; a second call is refused.
pub fn spawn_with(spawner: Spawner) -> Result<(), String> {
    SPAWNER
        .set(spawner)
        .map_err(|_| "the engine's spawner is already set".to_owned())
}

/// `Command::new` for a program that runs on the person's behalf: git, a
/// check's shell, an agent CLI. A bare name is looked up on `PATH` first, so
/// the spawn gets a path; a host's [`Spawner`] decides instead when it set one.
pub fn command(program: impl AsRef<OsStr>) -> Command {
    let program = program.as_ref();
    if let Some(spawner) = SPAWNER.get() {
        return spawner(program);
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    let bare = Path::new(program).components().count() == 1;
    match found_on(&path, program).filter(|_| bare && !cfg!(windows)) {
        Some(found) => Command::new(found),
        None => Command::new(program),
    }
}

/// The first executable file called `program` in the `PATH`-style `path`.
pub fn found_on(path: &OsStr, program: &OsStr) -> Option<PathBuf> {
    std::env::split_paths(path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(program))
        .find(|candidate| executable(candidate))
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

/// `CREATE_NO_WINDOW`, for a child that must not open a console window.
#[cfg(windows)]
pub const NO_WINDOW: u32 = 0x0800_0000;
