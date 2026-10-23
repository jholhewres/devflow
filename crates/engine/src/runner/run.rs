//! Running a command step, and streaming what it prints.
//!
//! Output arrives in pieces while the command runs rather than in one block at
//! the end. A test suite that takes twenty minutes shows its first line
//! immediately; buffering it would make a working command indistinguishable
//! from a hung one for twenty minutes.

use std::io::BufReader;
use std::path::Path;
use std::process::Stdio;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::descendants::{end_it_all, in_a_session_of_its_own};
use super::ended::{Ended, RunError};
use super::said::{each_line, Ceiling, Channel, Said};
use super::Context;

/// Runs `command` in `cwd`, calling `on_line` with each line as it arrives.
///
/// Every line says which of the command's two mouths it came from, and both
/// ceilings in [`crate::said`] hold: a line past [`super::said::LONGEST_LINE`]
/// arrives cut, and a run past [`MOST_OUTPUT`] stops being reported and says
/// so in [`Ended::output_cut`].
///
/// The context reaches the command only through the environment. The command
/// string itself is never built from it, so a value containing shell syntax
/// stays a value.
///
/// `on_pid` is handed the shell's process id the moment it exists, so a caller
/// can stop the run later. Without it a command run could only be waited out:
/// the card's stop and an update that was told to stop the work both answered
/// "not in flight here", and the run came back `lost` instead of `cancelled`.
/// What it stops is the shell, and through it everything the shell started:
/// the run gets a process group of its own, and the group ends together.
pub fn run(
    command: &str,
    cwd: &Path,
    context: &Context,
    timeout: Option<Duration>,
    on_pid: impl FnOnce(u32),
    mut on_line: impl FnMut(&Said),
) -> Result<Ended, RunError> {
    if command.trim().is_empty() {
        return Err(RunError::Empty);
    }

    let started = Instant::now();
    let mut spawning = crate::env::command("sh");
    spawning
        .arg("-c")
        .arg(command)
        .current_dir(cwd)
        .envs(context.environment())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = in_a_session_of_its_own(&mut spawning)
        .spawn()
        .map_err(|err| RunError::NotStarted(err.to_string()))?;
    on_pid(child.id());

    // stderr matters as much as stdout for a failing build, and interleaving
    // them keeps the order a person would have seen in a terminal — with the
    // channel on each line, so the order costs nothing to read back.
    let (tx, rx) = mpsc::channel::<Said>();
    let streams = [
        child
            .stdout
            .take()
            .map(|s| (Channel::Out, Box::new(s) as Box<dyn std::io::Read + Send>)),
        child
            .stderr
            .take()
            .map(|s| (Channel::Err, Box::new(s) as Box<dyn std::io::Read + Send>)),
    ];
    for (channel, stream) in streams.into_iter().flatten() {
        let tx = tx.clone();
        std::thread::spawn(move || {
            each_line(BufReader::new(stream), channel, |said| {
                let _ = tx.send(said);
            });
        });
    }
    drop(tx);

    // The run's own ceiling, kept here because this is the only place that
    // sees both channels.
    let mut ceiling = Ceiling::new();

    let mut timed_out = false;
    loop {
        // A short wait rather than a blocking read, so a command that prints
        // nothing can still be timed out.
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(said) => ceiling.report(&said, &mut on_line),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if let Some(limit) = timeout {
            if started.elapsed() > limit {
                end_it_all(&mut child);
                timed_out = true;
                break;
            }
        }
        if !timed_out {
            if let Ok(Some(_)) = child.try_wait() {
                // The process is gone, but the reader threads may still be
                // holding lines: `try_wait` racing `try_recv` dropped the last
                // line of stderr often enough to show up as a flaky test.
                //
                // Waiting for the channel to disconnect is the honest end —
                // every sender has finished — with a short ceiling so a child
                // that leaked the pipe to a grandchild cannot hold this open.
                let draining = Instant::now();
                while draining.elapsed() < Duration::from_secs(2) {
                    match rx.recv_timeout(Duration::from_millis(50)) {
                        Ok(said) => ceiling.report(&said, &mut on_line),
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                    }
                }
                break;
            }
        }
    }

    let status = child.wait().ok();
    Ok(Ended {
        exit_code: if timed_out {
            None
        } else {
            status.and_then(|s| s.code())
        },
        timed_out,
        duration_ms: started.elapsed().as_millis() as i64,
        output_cut: ceiling.cut,
    })
}

#[cfg(test)]
#[path = "run_tests.rs"]
mod tests;
