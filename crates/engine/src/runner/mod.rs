//! Running a check: a command in `sh -c`, its context only in the
//! environment, in a process group of its own, streamed and bounded, and the
//! test reports it left.

pub mod context;
pub mod descendants;
pub mod ended;
pub mod report;
pub mod run;
pub mod said;

pub use context::{Context, CONTEXT_KEYS};
pub use ended::{Ended, RunError};
pub use run::run;
pub use said::{Channel, Said};
