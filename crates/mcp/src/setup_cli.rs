//! `devflow setup`: the wizard. It finds the agent CLIs and IDEs here and
//! registers devflow with each the person says yes to, previews a
//! devflow.yaml for the project and writes it on a yes, switches devflow on
//! there, and offers Decisions. Every step asks first, on a terminal.

use std::path::Path;
use std::process::ExitCode;

use devflow_engine::detect;
use devflow_engine::folder::State;
use devflow_engine::preset::Preset;
use devflow_engine::{proposal, setup, Ask};
use serde_json::Map;

use crate::cli::confirmed;
use crate::consent::Consent;
use crate::credentials;
use crate::project::Project;
use crate::register::{self, Machine};

#[derive(clap::Args)]
pub struct Wizard {
    /// Where the project's setup starts: recommended or custom.
    #[arg(long, default_value = "recommended")]
    preset: String,
    /// Leave the agent CLIs and IDEs as they are.
    #[arg(long)]
    no_register: bool,
    /// Leave the project as it is.
    #[arg(long)]
    no_project: bool,
    /// Do not offer Decisions.
    #[arg(long)]
    no_jev: bool,
}

fn failed(why: &str) -> ExitCode {
    eprintln!("devflow: {why}");
    ExitCode::FAILURE
}

pub fn run(root: &Path, how: &Wizard) -> ExitCode {
    let Some(preset) = Preset::of(&how.preset) else {
        return failed(&format!(
            "`{}` is not a preset: recommended or custom",
            how.preset
        ));
    };
    let consent = Consent::of_user();
    let steps: [(&str, bool); 3] = [
        ("tools", !how.no_register),
        ("project", !how.no_project),
        ("jev", !how.no_jev),
    ];
    for (step, wanted) in steps {
        if !wanted {
            continue;
        }
        let done = match step {
            "tools" => tools(),
            "project" => project(root, preset, &consent),
            _ => decisions(),
        };
        if let Err(why) = done {
            return failed(&why);
        }
        println!();
    }
    println!("Done. `devflow doctor` checks it all again.");
    ExitCode::SUCCESS
}

fn tools() -> Result<(), String> {
    let machine = Machine::here();
    let bin = std::env::current_exe()
        .and_then(|path| path.canonicalize().or(Ok(path)))
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| register::NAME.to_owned());
    let found: Vec<register::Tool> = register::ALL
        .into_iter()
        .filter(|tool| machine.found(*tool))
        .collect();
    if found.is_empty() {
        println!("No agent CLI or IDE found here: install one, then run `devflow register`.");
        return Ok(());
    }
    let names: Vec<&str> = found.iter().map(|tool| tool.id()).collect();
    println!("Agent CLIs and IDEs found: {}", names.join(", "));
    for tool in found {
        if register::registered(tool, &bin, &machine) {
            println!("{}: devflow is already registered", tool.id());
            continue;
        }
        if !confirmed(&format!("Register devflow with {}?", tool.id()))? {
            continue;
        }
        for step in register::register(tool, &bin, &machine) {
            match register::carry(&step, false) {
                Ok(said) => println!("{}: {said}", tool.id()),
                Err(why) => eprintln!("{}: {why}", tool.id()),
            }
        }
    }
    Ok(())
}

fn project(root: &Path, preset: Preset, consent: &Consent) -> Result<(), String> {
    let project = Project::at(root);
    let layout = project.layout();
    println!("Project: {}", project.root.display());
    let state = project.read();
    if let State::Invalid(_, invalid) = &state {
        return Err(format!(
            "{} is invalid: {invalid}. Fix it, or ask an agent to with devflow's `set` tool.",
            layout.file
        ));
    }
    if matches!(state, State::Missing) {
        let machine = crate::flow::setup::machine(&project.root);
        let detected = detect::detected(&project.root, machine);
        let made = proposal::setup_in(&layout, &state, preset, &Map::new(), &detected)
            .map_err(|why| why.to_string())?;
        let planned = setup::with_unused(&project.root, &made.config, made.files.clone());
        println!("\n{}\n", made.yaml.trim_end());
        for file in setup::preview(&project.root, &planned) {
            println!("  {} {}", file.change, file.path);
        }
        let open = detect::open(&detected);
        if !open.is_empty() {
            println!("\nLeft open for you or your agent to settle:");
            for one in open {
                println!("  - {one}");
            }
        }
        if !confirmed("\nWrite these files?")? {
            println!("Nothing was written. An agent can set it up with devflow's `setup` tool.");
            return Ok(());
        }
        setup::write(&project.root, &planned)?;
        println!("Written. devflow never commits: these files are yours to commit.");
    } else {
        println!("{} is there already.", layout.file);
    }
    if consent.made(&project.root, Ask::Enable)
        && matches!(project.read(), State::Valid(_, ref config) if config.enabled)
    {
        println!("devflow is on here.");
        return Ok(());
    }
    if !confirmed("Switch devflow on in this project, on this machine?")? {
        println!("It stays off: `devflow config set enabled true` switches it on later.");
        return Ok(());
    }
    let state = project.read();
    if let State::Valid(_, config) = &state {
        if !config.enabled {
            let switched = proposal::switched_in(&project.layout(), &state, Ask::Enable)
                .map_err(|why| why.to_string())?;
            setup::write(&project.root, &switched.files)?;
        }
    }
    consent.remember(&project.root, Ask::Enable, true)?;
    println!("devflow is on here.");
    Ok(())
}

fn decisions() -> Result<(), String> {
    if credentials::source().is_some() {
        println!("Decisions: a key is set (`devflow jev status`).");
        return Ok(());
    }
    println!(
        "Decisions (Jev, through OpenRouter) judges a brief, a plan, review findings and the \
         gate on small states — never the diff. It is off until a key is set, and a project uses \
         it only where its devflow.yaml says `decisions: {{ use: true }}`."
    );
    if !confirmed("Set it up now?")? {
        println!("Later: `devflow jev setup`.");
        return Ok(());
    }
    crate::jev_cli::set_up(&crate::jev_cli::Setup::default())
}
