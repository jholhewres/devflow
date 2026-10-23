//! devflow: a short engineering flow for coding agents — briefing,
//! context, plan, execution, review, completion — in which work is done only
//! when its evidence says so.
//!
//! The engine is being extracted from devpit's Devflow (docs/plan.md). For
//! now this crate knows only where a project keeps its configuration.

pub mod locate;

pub use locate::{config_in, Found, Origin};
