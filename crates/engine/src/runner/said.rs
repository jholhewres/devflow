//! What a command said, which of its two mouths said it, and where it stops.
//!
//! Two things the runner used to lose. A failing build writes its reason to
//! stderr and its progress to stdout, and merging them into one stream threw
//! away the only mark that tells a reason from a step. And a command that
//! prints a megabyte a second — a test runner with a progress bar and no
//! terminal to rewrite — filled memory with output nobody would read.
//!
//! So a line arrives with its channel, and every ceiling here is applied
//! **before** the bytes are kept rather than after: a line is never allocated
//! past its limit and then measured, because a command that prints a gigabyte
//! on one line would have won that race.

use std::io::BufRead;

/// Which of a command's two outputs a line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Out,
    Err,
}

/// One line of a command's output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Said {
    pub channel: Channel,
    pub text: String,
    /// The line was longer than [`LONGEST_LINE`] and `text` is its beginning.
    pub cut: bool,
}

/// Past any line a compiler, a test runner or a linter writes, and short of
/// what a minified bundle printed by accident costs to hold.
pub const LONGEST_LINE: usize = 8 * 1024;

/// What one run may say before the rest is dropped. A suite that prints more
/// than this has stopped being read and started being stored.
pub const MOST_OUTPUT: usize = 2 * 1024 * 1024;

/// Reads `reader` a line at a time, handing each to `sink` with its channel.
///
/// Stops at end of stream or the first read error — a closed pipe is a command
/// that ended, not a failure to report.
pub(crate) fn each_line(mut reader: impl BufRead, channel: Channel, mut sink: impl FnMut(Said)) {
    let mut kept: Vec<u8> = Vec::new();
    let mut cut = false;
    loop {
        let available = match reader.fill_buf() {
            Ok([]) => break,
            Ok(bytes) => bytes,
            Err(_) => break,
        };
        let (upto, ends) = match available.iter().position(|byte| *byte == b'\n') {
            Some(at) => (at, true),
            None => (available.len(), false),
        };
        keep(&mut kept, &available[..upto], &mut cut);
        reader.consume(if ends { upto + 1 } else { upto });
        if ends {
            sink(said(&mut kept, channel, &mut cut));
        }
    }
    // A last line with no newline after it is still a line.
    if !kept.is_empty() {
        sink(said(&mut kept, channel, &mut cut));
    }
}

/// Keeps what fits under the ceiling and counts the rest as cut.
///
/// The slice is never appended whole and trimmed afterwards: `kept` cannot
/// grow past [`LONGEST_LINE`], whatever arrives.
fn keep(kept: &mut Vec<u8>, arriving: &[u8], cut: &mut bool) {
    let room = LONGEST_LINE.saturating_sub(kept.len());
    if arriving.len() > room {
        *cut = true;
    }
    kept.extend_from_slice(&arriving[..room.min(arriving.len())]);
}

/// Takes the line that has been built, leaving the buffer ready for the next.
///
/// Lossy on purpose: a command may print bytes that are no text at all, and a
/// build log is not worth losing to one of them.
fn said(kept: &mut Vec<u8>, channel: Channel, cut: &mut bool) -> Said {
    let text = String::from_utf8_lossy(kept)
        .trim_end_matches('\r')
        .to_owned();
    kept.clear();
    Said {
        channel,
        text,
        cut: std::mem::take(cut),
    }
}

/// How much a run has said, and whether it has said too much.
pub(crate) struct Ceiling {
    spoken: usize,
    /// The run passed [`MOST_OUTPUT`] and the rest was dropped.
    pub cut: bool,
}

impl Ceiling {
    pub(crate) fn new() -> Self {
        Self {
            spoken: 0,
            cut: false,
        }
    }

    /// Hands `said` on while the run is still under the ceiling.
    ///
    /// Silent past it rather than louder: a command drowning the window is
    /// already the problem, and one notice is said by `Ended::output_cut`.
    pub(crate) fn report(&mut self, said: &Said, on_line: &mut impl FnMut(&Said)) {
        if self.cut {
            return;
        }
        self.spoken = self.spoken.saturating_add(said.text.len());
        if self.spoken > MOST_OUTPUT {
            self.cut = true;
            return;
        }
        on_line(said);
    }
}

#[cfg(test)]
#[path = "said_tests.rs"]
mod tests;
