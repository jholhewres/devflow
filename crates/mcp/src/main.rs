//! `devflow`: the MCP server agent CLIs start, and the few commands a person
//! runs to set it up and check on it.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod register;
mod server;
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
    /// Register devflow with the agent CLIs and IDEs installed here.
    Register(Registering),
    /// Take devflow out of them again.
    Unregister(Registering),
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
        Command::Register(how) => registering(&how, true),
        Command::Unregister(how) => registering(&how, false),
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
    let said = tools::status_of(root);
    if said["state"] == "found" {
        let read_as = if said["layout"] == "devpit" {
            " (devpit's Devflow layout, read where it is)"
        } else {
            ""
        };
        println!(
            "Configuration: {}{read_as}",
            said["path"].as_str().unwrap_or_default()
        );
        ExitCode::SUCCESS
    } else {
        println!(
            "No configuration in {}: none of {} is there.",
            root.display(),
            devflow_engine::locate::CANDIDATES.join(", ")
        );
        ExitCode::from(1)
    }
}
