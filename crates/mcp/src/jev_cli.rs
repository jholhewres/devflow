//! `devflow jev`: Decisions through OpenRouter, set up by the person. Off
//! until a key is kept; the key is read from `OPENROUTER_API_KEY` or kept in
//! `$XDG_CONFIG_HOME/devflow/credentials` (mode 0600), never in a
//! repository, and never printed.

use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::Path;
use std::process::ExitCode;

use serde_json::json;

use crate::credentials;
use crate::decisions::deciding::{self, Asking, Decided};
use crate::decisions::log::Log;
use crate::decisions::rubric::{Rubric, Threshold};
use crate::decisions::settings::Settings;

#[derive(clap::Args)]
pub struct Setup {
    /// The model to ask. typesafe/jev-1.13 when left out.
    #[arg(long)]
    model: Option<String>,
    /// The provider's address: https, or a service on this machine.
    #[arg(long)]
    url: Option<String>,
    /// What Decisions may spend in a day, in dollars.
    #[arg(long, value_name = "USD")]
    daily_cap: Option<f64>,
    /// Read the key from stdin, for a key manager's pipe; else it is asked on
    /// the terminal without echo, or `OPENROUTER_API_KEY` is used as it is.
    #[arg(long)]
    key_stdin: bool,
}

fn failed(why: &str) -> ExitCode {
    eprintln!("devflow: {why}");
    ExitCode::FAILURE
}

/// The key, asked without echo on a terminal.
fn asked_key() -> Result<String, String> {
    print!("OpenRouter key (input hidden; Enter keeps the one set): ");
    let _ = std::io::stdout().flush();
    let quiet = echo(false);
    let mut said = String::new();
    let read = std::io::stdin().lock().read_line(&mut said);
    if quiet {
        echo(true);
    }
    println!();
    read.map_err(|err| err.to_string())?;
    Ok(said.trim().to_owned())
}

/// Turns the terminal's echo off or on; whether it could.
fn echo(on: bool) -> bool {
    #[cfg(unix)]
    {
        std::process::Command::new("stty")
            .arg(if on { "echo" } else { "-echo" })
            .stdin(std::process::Stdio::inherit())
            .status()
            .is_ok_and(|status| status.success())
    }
    #[cfg(not(unix))]
    {
        let _ = on;
        false
    }
}

/// A key as a provider issues one: one word, not too long.
pub fn plain_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 512 && !key.chars().any(char::is_whitespace)
}

pub fn setup(how: &Setup) -> ExitCode {
    let Some(file) = Settings::file() else {
        return failed("no home folder to keep the settings in");
    };
    let mut settings = Settings::read_at(&file);
    if let Some(model) = &how.model {
        settings.model = model.trim().to_owned();
    }
    if let Some(url) = &how.url {
        settings.url = url.trim().trim_end_matches('/').to_owned();
    }
    if let Some(cap) = how.daily_cap {
        settings.daily_cap_usd = cap;
    }
    if let Err(why) = settings.checked() {
        return failed(&why);
    }
    let key = if how.key_stdin {
        let mut said = String::new();
        if std::io::stdin()
            .take(4096)
            .read_to_string(&mut said)
            .is_err()
        {
            return failed("the key could not be read from stdin");
        }
        Some(said.trim().to_owned())
    } else if std::io::stdin().is_terminal() && credentials::source() != Some(credentials::ENV) {
        match asked_key() {
            Ok(key) if key.is_empty() => None,
            Ok(key) => Some(key),
            Err(why) => return failed(&why),
        }
    } else {
        None
    };
    if let Some(key) = &key {
        if !plain_key(key) {
            return failed("that is not a key");
        }
        let Some(kept) = credentials::file() else {
            return failed("no home folder to keep the key in");
        };
        if let Err(why) = credentials::write_key(&kept, key) {
            return failed(&why);
        }
    }
    if let Err(why) = settings.write_at(&file) {
        return failed(&why);
    }
    println!(
        "Decisions: {} at {}, model {}, up to ${:.2} a day.",
        settings.provider,
        settings.base(),
        settings.model(),
        settings.daily_cap_usd
    );
    match credentials::source() {
        Some(credentials::ENV) => println!("Key: from {}.", credentials::ENV),
        Some(_) => println!(
            "Key: kept in {} (readable by you only).",
            credentials::file()
                .map(|file| file.display().to_string())
                .unwrap_or_default()
        ),
        None => println!(
            "Key: none yet, so Decisions stays off. Set {} or run this again on a terminal.",
            credentials::ENV
        ),
    }
    println!(
        "A project asks Decisions once its devflow.yaml says `decisions: {{ use: true }}`; \
         `devflow jev test` checks the key."
    );
    ExitCode::SUCCESS
}

pub fn status() -> ExitCode {
    let settings = Settings::of_user();
    let log = Log::of_user();
    let spent = log.spend_since(deciding::today(deciding::now()));
    println!(
        "Provider: {} at {}\nModel: {}\nDaily cap: ${:.2} (spent today: ${spent:.4})",
        settings.provider,
        settings.base(),
        settings.model(),
        settings.daily_cap_usd
    );
    match credentials::source() {
        Some(source) => println!("Key: set ({source})"),
        None => println!("Key: none: Decisions is off (`devflow jev setup`)"),
    }
    if !settings.opted_out.is_empty() {
        println!("Never sent: {}", settings.opted_out.join(", "));
    }
    ExitCode::SUCCESS
}

/// One question with an obvious answer, through the path every decision
/// takes: whether the key and the provider answer, and what it cost.
pub fn test() -> ExitCode {
    let settings = Settings::of_user();
    let conf = settings.conf(credentials::openrouter_key());
    let rubric = Rubric {
        name: "devflow.test".to_owned(),
        version: Some("1".to_owned()),
        questions: json!({ "blue": { "type": "noul", "instructions": "Does the state say the sky is blue?" } }),
        thresholds: [(
            "blue".to_owned(),
            Threshold {
                min: Some(0.5),
                ..Threshold::default()
            },
        )]
        .into(),
    };
    let state = json!("The sky is blue.");
    let asking = Asking {
        project_id: None,
        card_id: None,
        gate: "devflow.test",
        mode: "shadow",
        rubric: Some(&rubric),
        state: &state,
        questions: &rubric.questions,
    };
    let (decided, _) = deciding::decide_logged(&Log::of_user(), &conf, &asking, deciding::now());
    match decided {
        Decided::Answered {
            answers,
            cost_usd,
            latency_ms,
            ..
        } => {
            let p = crate::decisions::rubric::scalar(&answers["blue"]).unwrap_or_default();
            println!("Decisions answered: p={p:.2} in {latency_ms} ms for ${cost_usd:.5}.");
            ExitCode::SUCCESS
        }
        Decided::Skipped(skip) => failed(&skip.reason()),
    }
}

/// Takes the kept key away, which turns Decisions off where no
/// `OPENROUTER_API_KEY` is set.
pub fn forget() -> ExitCode {
    let Some(file) = credentials::file() else {
        return failed("no home folder");
    };
    match credentials::forget_key(&file) {
        Ok(true) => println!("The kept key is gone."),
        Ok(false) => println!("No key was kept."),
        Err(why) => return failed(&why),
    }
    if credentials::source() == Some(credentials::ENV) {
        println!("{} is still set in this shell.", credentials::ENV);
    }
    ExitCode::SUCCESS
}

/// Keeps a project's state from ever being sent, or lets it be again.
pub fn send(root: &Path, yes: bool) -> ExitCode {
    let Some(file) = Settings::file() else {
        return failed("no home folder");
    };
    let mut settings = Settings::read_at(&file);
    let project = crate::flow::jev::project_id(&crate::project::Project::at(root));
    settings.opted_out.retain(|one| *one != project);
    if !yes {
        settings.opted_out.push(project.clone());
    }
    match settings.write_at(&file) {
        Ok(()) => {
            println!(
                "{project}: its state is {} to Decisions.",
                if yes { "sent" } else { "never sent" }
            );
            ExitCode::SUCCESS
        }
        Err(why) => failed(&why),
    }
}

#[cfg(test)]
#[path = "jev_cli_tests.rs"]
mod tests;
