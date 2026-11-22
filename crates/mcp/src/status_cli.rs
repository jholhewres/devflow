//! `devflow status`, `devflow persona show` and `devflow version`: what
//! devflow and the project here are, read and printed, nothing changed.

use std::process::ExitCode;

use crate::{flow, host, project, server};

pub fn version(json: bool) -> ExitCode {
    if json {
        println!(
            "{}",
            serde_json::json!({ "version": env!("CARGO_PKG_VERSION"), "protocols": host::PROTOCOLS })
        );
    } else {
        println!("devflow {}", env!("CARGO_PKG_VERSION"));
    }
    ExitCode::SUCCESS
}

pub fn status(root: &std::path::Path) -> ExitCode {
    let project = project::Project::at(root);
    let server = server::Server::new(root);
    let said = flow::setup::status_of(&project, &server);
    let state = said["state"].as_str().unwrap_or_default();
    if state == "no file" {
        println!(
            "No configuration in {}: none of {} is there.",
            project.root.display(),
            devflow_engine::locate::CANDIDATES.join(", ")
        );
        return ExitCode::from(1);
    }
    let legacy = if said["folder"] == devflow_engine::folder::LEGACY {
        " (devpit's Devflow layout, read where it is)"
    } else {
        ""
    };
    println!(
        "Configuration: {}{legacy}\nState: {state}\nNext: {}",
        said["file"].as_str().unwrap_or_default(),
        said["next"].as_str().unwrap_or_default()
    );
    if let Some(note) = said["note"].as_str() {
        println!("Note: {note}");
    }
    if let Some(rows) = said["models"]["origins"].as_array() {
        println!(
            "Models (preset {}, the session on {}):",
            said["models"]["preset"].as_str().unwrap_or_default(),
            said["models"]["agent"].as_str().unwrap_or_default()
        );
        for line in models_table(rows) {
            println!("  {line}");
        }
    }
    ExitCode::SUCCESS
}

/// `devflow status --attack`: the project's attack numbers, as JSON.
pub fn attack_status(root: &std::path::Path) -> ExitCode {
    let project = project::Project::at(root);
    let server = server::Server::new(root);
    let said = flow::setup::status_of(&project, &server);
    match said.get("attack") {
        Some(attack) => {
            println!(
                "{}",
                serde_json::to_string_pretty(attack).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        None => {
            println!("No attack has run in this project yet.");
            ExitCode::SUCCESS
        }
    }
}

/// Each stage's and reviewer's model as a few columns: the stage, the
/// reviewer when it is one, the model said, what it runs on when that
/// differs, and where it came from.
fn models_table(rows: &[serde_json::Value]) -> Vec<String> {
    let text =
        |row: &serde_json::Value, key: &str| row[key].as_str().unwrap_or_default().to_owned();
    let cells: Vec<[String; 3]> = rows
        .iter()
        .map(|row| {
            let stage = match row["who"].as_str() {
                Some(who) => format!("{} [{who}]", text(row, "stage")),
                None => text(row, "stage"),
            };
            let said = row["said"].as_str().unwrap_or("-");
            let model = match (row["runs_on"].as_str(), said) {
                (Some(on), _) if on != said => format!("{said} ({on})"),
                // A tier this CLI has no model for leaves it on its own default.
                (None, "small" | "large") => format!("{said} (the CLI's default)"),
                _ => said.to_owned(),
            };
            [stage, model, text(row, "from")]
        })
        .collect();
    let wide = |at: usize| {
        cells
            .iter()
            .map(|row| row[at].chars().count())
            .max()
            .unwrap_or(0)
    };
    let (stage, model) = (wide(0), wide(1));
    cells
        .iter()
        .map(|row| format!("{:<stage$}  {:<model$}  {}", row[0], row[1], row[2]))
        .collect()
}

/// `devflow persona show <name>`: the effective persona and what it was read
/// from.
pub fn persona_show(root: &std::path::Path, name: &str) -> ExitCode {
    let project = project::Project::at(root);
    let teams = project.teams();
    let personal = project::personal_reviewers();
    let personas = devflow_engine::review::Personas {
        dialect: &devflow_engine::Dialect::DEVFLOW,
        personal: personal.as_deref(),
        teams: &teams,
    };
    match devflow_engine::review::effective_persona(&project.root, personas, name) {
        Ok(effective) => {
            println!("devflow {}", env!("CARGO_PKG_VERSION"));
            println!("{}", devflow_engine::review::persona_line(name, &effective));
            println!();
            println!("{}", effective.text);
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("devflow persona: {why}");
            ExitCode::FAILURE
        }
    }
}
