//! The call running now, as its host sees it: whether its client cancelled
//! it, and where its progress goes. The MCP server runs one call at a time,
//! so these are the process's own: set when a call starts, cleared when it
//! ends, and read by every wait on a process the call started (a reviewer,
//! a check, an exploit), which ends that process's group once cancelled.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// Where a call's progress is said: one line per step done.
pub type Progress = Box<dyn Fn(&str) + Send + Sync>;

static CANCELLED: AtomicBool = AtomicBool::new(false);
static PROGRESS: Mutex<Option<Progress>> = Mutex::new(None);

/// A call starts: not cancelled, its progress said to `progress` when its
/// client asked for it.
pub fn begin(progress: Option<Progress>) {
    CANCELLED.store(false, Ordering::SeqCst);
    if let Ok(mut said) = PROGRESS.lock() {
        *said = progress;
    }
}

/// The call ended: nothing more is said of it.
pub fn end() {
    begin(None);
}

/// The client cancelled the call: each process it started is ended at its
/// next look, and nothing more is started.
pub fn cancel() {
    CANCELLED.store(true, Ordering::SeqCst);
}

/// Whether the client cancelled the call running now.
pub fn cancelled() -> bool {
    CANCELLED.load(Ordering::SeqCst)
}

/// One step of the call done, said to its client when it asked.
pub fn progress(step: &str) {
    if let Ok(said) = PROGRESS.lock() {
        if let Some(said) = said.as_ref() {
            said(step);
        }
    }
}
