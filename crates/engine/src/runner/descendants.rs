//! Ending a command run, and everything it started.
//!
//! A command step is almost never one process. `make test` is `sh`'s child and
//! `cargo` is its grandchild and the test binary is its great-grandchild, and
//! signalling the shell alone leaves the suite running under a card that says
//! it stopped. That is worse than no Cancel at all: the window reports an end
//! that did not happen, and the next run fights the last one for the port, the
//! lock file, the tmux pane.
//!
//! So the shell is given a session of its own at spawn, which makes it the
//! leader of a process group nothing else is in, and the whole group is
//! signalled together. The group exists because this module created it — this
//! never signals a group it did not make, which is also why the tmux server,
//! living in its own session, is out of reach here by construction.
//!
//! Windows has no sessions or signals: the shell gets a process group of its
//! own, and the tree under it is ended by `taskkill /T` — the same promise.

use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// How long the group is given to end on the polite signal before the one it
/// cannot catch. Long enough for a test runner to drop a lock file, short
/// enough that a person waiting on Cancel does not wonder.
const GRACE: Duration = Duration::from_millis(500);

/// How often the group is looked at while it ends.
const LOOK: Duration = Duration::from_millis(20);

/// Puts the command in a session of its own, so its descendants share one
/// process group and can be ended together.
#[cfg(unix)]
pub fn in_a_session_of_its_own(command: &mut Command) -> &mut Command {
    use std::io;
    use std::os::unix::process::CommandExt;
    // SAFETY: `setsid` is async-signal-safe and touches nothing shared with
    // this process after the fork — which is the whole contract of `pre_exec`.
    unsafe {
        command.pre_exec(|| match libc::setsid() {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        })
    }
}

/// A process group of its own, which is what `taskkill /T` ends as one tree.
#[cfg(windows)]
pub fn in_a_session_of_its_own(command: &mut Command) -> &mut Command {
    use std::os::windows::process::CommandExt;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    // Both: flags are set, not added, and this would drop the one that keeps
    // a console window from opening.
    command.creation_flags(CREATE_NEW_PROCESS_GROUP | crate::env::NO_WINDOW)
}

/// Ends the run and everything under it, and does not return until the group
/// is gone.
///
/// Terminate first, so a runner that cleans up after itself gets to; then kill
/// what is left. Reporting an end before observing one is the bug this module
/// exists to remove, so the wait is not optional.
#[cfg(unix)]
pub fn end_it_all(child: &mut Child) {
    let group = child.id() as i32;
    signal(group, libc::SIGTERM);
    if gone(child, GRACE) {
        return;
    }
    signal(group, libc::SIGKILL);
    // SIGKILL cannot be caught, so what is left is the kernel reaping. A
    // group that outlives this is a process stuck in the kernel, which no
    // signal would have moved either.
    gone(child, GRACE);
}

/// The Windows half: the whole tree, forced, then waited for.
#[cfg(windows)]
pub fn end_it_all(child: &mut Child) {
    let _ = crate::env::command("taskkill")
        .args(["/T", "/F", "/PID", &child.id().to_string()])
        .output();
    gone(child, GRACE);
}

/// Signals the whole group, by the negative pid `kill` reads as one.
///
/// Only a group this module made: `group` is the pid of a shell spawned
/// through [`in_a_session_of_its_own`], which `setsid` made the leader.
#[cfg(unix)]
fn signal(group: i32, signal: i32) {
    // SAFETY: a signal to a pid this process owns; the worst answer is ESRCH,
    // which is the group already being gone.
    unsafe {
        libc::kill(-group, signal);
    }
}

/// Waits for the shell itself to be reaped, up to `patience`.
///
/// The shell is the group's leader, so it outlives what it started in every
/// ordinary shape of this: it is waiting on them.
fn gone(child: &mut Child, patience: Duration) -> bool {
    let waited = Instant::now();
    while waited.elapsed() < patience {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return true,
            Ok(None) => std::thread::sleep(LOOK),
        }
    }
    false
}
