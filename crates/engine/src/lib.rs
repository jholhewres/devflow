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
#[doc(hidden)]
pub mod agents;
#[doc(hidden)]
pub mod attack;
#[doc(hidden)]
pub mod attack_metrics;
#[doc(hidden)]
pub mod attack_report;
#[doc(hidden)]
pub mod autopilot;
#[doc(hidden)]
pub mod available;
pub mod brief;
pub mod calibrate;
#[doc(hidden)]
pub mod call;
pub mod config;
pub mod criteria;
pub mod detect;
pub mod dialect;
mod edit;
pub mod env;
pub mod evidence;
pub mod findings;
pub(crate) mod flow;
pub mod folder;
pub mod fresh;
#[doc(hidden)]
pub mod fsguard;
pub mod gate;
pub mod git;
#[doc(hidden)]
pub mod home;
pub mod jev;
pub mod layers;
pub mod locate;
#[doc(hidden)]
pub mod models;
mod node;
#[doc(hidden)]
pub mod payloads;
pub mod pinning;
pub mod plan;
#[doc(hidden)]
pub mod playwright;
pub mod plugin;
pub mod preset;
pub mod proposal;
pub mod publish;
#[doc(hidden)]
pub mod render;
pub mod review;
pub mod runner;
pub mod runs;
#[doc(hidden)]
pub mod sandbox;
#[doc(hidden)]
pub mod scale;
pub mod security;
pub mod setup;
pub mod skills;
#[doc(hidden)]
pub mod stack;
pub mod stage;
pub mod started;
#[doc(hidden)]
pub mod vault;
#[doc(hidden)]
pub mod verdict;
pub mod work;
#[doc(hidden)]
pub mod workspace;

pub use config::{Config, Invalid};
pub use dialect::{Assets, Dialect};
pub use folder::State;
pub use locate::{config_in, Found, Origin};
pub use proposal::{Ask, Proposal};
