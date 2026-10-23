//! devflow: a short engineering flow for coding agents — briefing, context,
//! plan, execution, review, completion — in which work is done only when its
//! evidence says so.
//!
//! A project configures it in `devflow.yaml` (or `.devflow/devflow.yaml`;
//! devpit's `.devpit/devflow/devflow.yaml` is read where it is). This crate
//! reads and writes that folder, detects what a setup starts from, writes a
//! brief and a plan as the text of the work items they become, runs checks
//! into the evidence kept for an item, has its change reviewed by agent CLIs
//! headless, and gates the item on that evidence.

pub mod adhoc;
pub mod agents;
pub mod autopilot;
pub mod available;
pub mod brief;
pub mod calibrate;
pub mod config;
pub mod criteria;
pub mod detect;
pub mod env;
pub mod evidence;
pub mod findings;
pub mod flow;
pub mod folder;
pub mod fsguard;
pub mod gate;
pub mod git;
pub mod home;
pub mod jev;
pub mod layers;
pub mod locate;
mod node;
pub mod pinning;
pub mod plan;
pub mod playwright;
pub mod plugin;
pub mod preset;
pub mod proposal;
pub mod publish;
pub mod render;
pub mod review;
pub mod runner;
pub mod runs;
pub mod scale;
pub mod setup;
pub mod skills;
pub mod stage;
pub mod started;
pub mod verdict;
pub mod work;

pub use config::{Config, Invalid};
pub use folder::State;
pub use locate::{config_in, Found, Origin};
pub use proposal::{Ask, Proposal};
