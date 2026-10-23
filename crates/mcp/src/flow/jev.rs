//! Jev in devflow: one of the flow's rubrics asked of Decisions, for a
//! project whose devflow.yaml uses it. Off unless set up.

use devflow_engine::config::{Config, Mode};
use devflow_engine::jev::{self as rules, DevflowDecisions, Said};
use devflow_engine::Ask;
use serde_json::{json, Value};

use crate::project::Project;
use crate::server::Server;

/// `enforce` acts only once the person moved it there in a terminal.
pub fn mode_of(server: &Server, project: &Project, config: &Config) -> Mode {
    if config.decisions.mode == Mode::Enforce && server.consent.made(&project.root, Ask::Enforce) {
        Mode::Enforce
    } else {
        Mode::Shadow
    }
}

/// The Decisions key, when one is set up: never printed, never logged.
pub fn key() -> Option<String> {
    crate::credentials::openrouter_key()
}

/// Jev, as one project's flow asks it.
pub struct Jev {
    mode: Mode,
}

impl Jev {
    /// Jev for this project, wherever devflow.yaml says `use`.
    pub fn of(
        server: &Server,
        project: &Project,
        config: &Config,
        _item: Option<&str>,
        _criteria: &[String],
    ) -> Option<Jev> {
        config.decisions.use_.then(|| Jev {
            mode: mode_of(server, project, config),
        })
    }

    /// Whether Decisions can answer at all.
    pub fn answers(&self) -> bool {
        false
    }

    pub fn state(&self) -> DevflowDecisions {
        rules::decisions_state(true, false, key().is_some(), None)
    }

    /// The rubric `name` asked about `state`.
    pub fn judge(&self, name: &str, _state: &Value) -> Said {
        Said {
            rubric: name.to_owned(),
            decision: None,
            mode: self.mode,
            outcome: "skipped".to_owned(),
            verdicts: Value::Null,
            answers: Value::Null,
            skipped: Some("no Decisions provider is set up: `devflow jev setup`".to_owned()),
        }
    }
}

/// Where Decisions stands for a reply, with the Jev it asked, if any.
pub fn decisions_of(config: &Config, jev: Option<&Jev>) -> Value {
    let state = jev.map_or_else(
        || rules::decisions_state(config.decisions.use_, false, key().is_some(), None),
        Jev::state,
    );
    json!(state)
}
