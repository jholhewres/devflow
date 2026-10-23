//! What a command run answers, and the two ways it never starts.
//!
//! Apart from the runner because they are the shape of its answer rather than
//! part of running: the runner has a ceiling, and a type moved out of it is
//! room for the run itself.

#[derive(Debug)]
pub enum RunError {
    NotStarted(String),
    Empty,
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::NotStarted(why) => write!(f, "the command could not be started: {why}"),
            RunError::Empty => write!(f, "no command to run"),
        }
    }
}

impl std::error::Error for RunError {}

/// How a command run ended.
#[derive(Debug, Clone, PartialEq)]
pub struct Ended {
    /// `None` when the command was killed for running past its timeout.
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: i64,
    /// The run said more than `said::MOST_OUTPUT` and the rest was dropped.
    /// A card showing this output is showing its beginning, and says so.
    pub output_cut: bool,
}
