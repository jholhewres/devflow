//! `evidence`: a work item's checks run in the project, the run kept in
//! `<dir>/runs/<item>/<time>/`, and a comment on the item naming its files.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use devflow_engine::evidence::{self, Card, Given};
use devflow_engine::runs::Attached;
use serde_json::Value;

use super::{as_engine, context_of, item_here, links, redact, signed};
use crate::server::Server;

/// How long all of one call's checks may take: past the longest a client
/// waits on a tool, the answer would come to nobody.
pub const BUDGET: Duration = Duration::from_secs(50 * 60);

pub fn evidence(server: &Server, params: Value) -> Result<Value, String> {
    let project = server.project();
    let state = project.read();
    let config = super::config_for(&project, &state, &server.consent, "execution")?;
    let asked = evidence::asked(&as_engine(&params))?;
    let item = item_here(&project, &asked.card)?;
    let context = context_of(&project, &item);
    let runs = project.runs();
    let found = evidence::gathered(&Given {
        root: &project.root,
        runs: &runs,
        locks: &project.locks(),
        config,
        asked: &asked,
        card: Card {
            id: &item.id,
            title: &item.title,
            body: &item.body,
        },
        context: &context,
        budget: BUDGET,
        redact: &redact,
        at: SystemTime::now(),
    })?;
    let run = PathBuf::from(&found.folder);
    let files = found.files(&run);
    let attached = Attached {
        names: files.clone(),
        left_out: Vec::new(),
    };
    signed(
        &project,
        &item.id,
        &evidence::comment(&found, &links(&project, &run, &files)),
    );
    let under = run
        .strip_prefix(&project.root)
        .map(|relative| relative.display().to_string())
        .unwrap_or_else(|_| found.folder.clone());
    Ok(evidence::summary(&found, &attached, &under))
}
