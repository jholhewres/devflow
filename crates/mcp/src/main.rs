//! `devflow`: the MCP server agent CLIs start, and the few commands a person
//! runs to set it up and check on it.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod cli;
mod consent;
mod credentials;
mod decisions;
mod doctor;
mod flow;
mod hook;
mod jev_cli;
mod project;
mod register;
mod server;
mod setup_cli;
mod tools;

/// An evidence-gated engineering flow for coding agents: briefing, context,
/// plan, execution, review and completion, where work is done only when its
/// checks, its criteria and its review say so. Served to agent CLIs as an MCP
/// server.
#[derive(Parser)]
#[command(name = "devflow", version, arg_required_else_help = true)]
struct Cli {
    /// The project's root. The current directory when left out.
    #[arg(long, global = true, value_name = "DIR")]
    root: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve MCP over stdio. Agent CLIs run this; a person does not.
    Mcp,
    /// Say which configuration applies to the project, if any.
    Status,
    /// Set devflow up: register it with the agent CLIs found here, write the
    /// project's devflow.yaml and switch it on, and offer Decisions. Asks
    /// before each step.
    Setup(setup_cli::Wizard),
    /// Check this machine and this project for what devflow needs.
    Doctor,
    /// Register devflow with the agent CLIs and IDEs installed here.
    Register(Registering),
    /// Take devflow out of them again.
    Unregister(Registering),
    /// Read or change the project's devflow.yaml. `config set enabled true`
    /// switches devflow on, after your yes on a terminal.
    Config {
        #[command(subcommand)]
        action: Configuring,
    },
    /// Decisions (Jev) through OpenRouter: opt-in, the key never in a repository.
    Jev {
        #[command(subcommand)]
        action: Judging,
    },
    /// The project's own stages.
    Stage {
        #[command(subcommand)]
        action: Staging,
    },
    /// What an agent CLI's hook runs: the gate at a Stop, the item's context
    /// at a session's start. Reads the hook's payload on stdin.
    Hook {
        #[arg(value_enum)]
        event: hook::Event,
        /// The CLI the hook belongs to: claude, codex, gemini, cursor, opencode.
        #[arg(long, default_value = "claude")]
        agent: String,
    },
}

#[derive(Subcommand)]
enum Configuring {
    /// Print the configuration that applies, or one field by its dotted path.
    Get { path: Option<String> },
    /// Change one field by its dotted path, after your yes.
    Set { path: String, value: String },
}

#[derive(Subcommand)]
enum Judging {
    /// Set the provider, the model, the day's cap and the key.
    Setup(jev_cli::Setup),
    /// How Decisions is set up here, and what it spent today.
    Status,
    /// Ask one trivial question, to check the key and the provider.
    Test,
    /// Take the kept key away.
    Forget,
    /// Send this project's state to Decisions again.
    Send,
    /// Never send this project's state to Decisions.
    Withhold,
}

#[derive(Subcommand)]
enum Staging {
    /// Let a team layer's command for an own stage run here, at its commit.
    Confirm { name: String },
}

#[derive(clap::Args)]
struct Registering {
    /// Only these, comma-separated: claude, codex, gemini, cursor, opencode,
    /// vscode. Every one found here when left out.
    #[arg(long, value_name = "LIST")]
    tools: Option<String>,
    /// Say what would change and change nothing.
    #[arg(long)]
    dry_run: bool,
    /// The binary the configs name. This one when left out.
    #[arg(long, value_name = "PATH")]
    bin: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let root = cli.root.unwrap_or_else(|| PathBuf::from("."));
    match cli.command {
        Command::Mcp => ExitCode::from(server::serve(&root) as u8),
        Command::Status => status(&root),
        Command::Setup(how) => setup_cli::run(&root, &how),
        Command::Doctor => doctor::run(&root),
        Command::Register(how) => registering(&how, true),
        Command::Unregister(how) => registering(&how, false),
        Command::Hook { event, agent } => hook::run(event, &agent, &root),
        Command::Config { action } => match action {
            Configuring::Get { path } => cli::get(&root, path.as_deref()),
            Configuring::Set { path, value } => {
                cli::set(&root, &path, &value, &consent::Consent::of_user())
            }
        },
        Command::Jev { action } => match action {
            Judging::Setup(how) => jev_cli::setup(&how),
            Judging::Status => jev_cli::status(),
            Judging::Test => jev_cli::test(),
            Judging::Forget => jev_cli::forget(),
            Judging::Send => jev_cli::send(&root, true),
            Judging::Withhold => jev_cli::send(&root, false),
        },
        Command::Stage {
            action: Staging::Confirm { name },
        } => cli::confirm_stage(&root, &name, &consent::Consent::of_user()),
    }
}

fn registering(how: &Registering, on: bool) -> ExitCode {
    let machine = register::Machine::here();
    let tools = match register::chosen(how.tools.as_deref(), &machine) {
        Ok(tools) => tools,
        Err(why) => {
            eprintln!("devflow: {why}");
            return ExitCode::from(2);
        }
    };
    if tools.is_empty() {
        println!("No agent CLI or IDE found here; name one with --tools.");
        return ExitCode::SUCCESS;
    }
    // Configs read without the shell's PATH get the binary whole.
    let bin = how
        .bin
        .clone()
        .map(Ok)
        .unwrap_or_else(std::env::current_exe)
        .and_then(|path| path.canonicalize().or(Ok(path)))
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| register::NAME.to_owned());
    let mut failed = false;
    for tool in tools {
        let steps = if on {
            register::register(tool, &bin, &machine)
        } else {
            register::unregister(tool, &machine)
        };
        for step in steps {
            match register::carry(&step, how.dry_run) {
                Ok(said) => println!("{}: {said}", tool.id()),
                Err(why) => {
                    failed = true;
                    eprintln!("{}: {why}", tool.id());
                }
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn status(root: &std::path::Path) -> ExitCode {
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
    ExitCode::SUCCESS
}
