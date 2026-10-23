//! The `stagegate` command line.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use stagegate_core::Origin;

/// An evidence-gated engineering flow for coding agents: briefing, context,
/// plan, execution, review and completion, where work is done only when its
/// checks, its criteria and its review say so.
#[derive(Parser)]
#[command(name = "stagegate", version, arg_required_else_help = true)]
struct Cli {
    /// The project's root. The current directory when left out.
    #[arg(long, global = true, value_name = "DIR")]
    root: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Say which configuration applies to the project, if any.
    Status,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let root = cli.root.unwrap_or_else(|| PathBuf::from("."));
    match cli.command {
        Command::Status => status(&root),
    }
}

fn status(root: &std::path::Path) -> ExitCode {
    let Some(found) = stagegate_core::config_in(root) else {
        println!(
            "No configuration in {}: none of {}, {}/{} or {} is there.",
            root.display(),
            stagegate_core::locate::FILE,
            stagegate_core::locate::DIR,
            stagegate_core::locate::FILE,
            stagegate_core::locate::DEVPIT,
        );
        return ExitCode::from(1);
    };
    let read_as = match found.origin {
        Origin::Root | Origin::Folder => "",
        Origin::Devpit => " (devpit's Devflow layout, read where it is)",
    };
    println!("Configuration: {}{read_as}", found.path.display());
    ExitCode::SUCCESS
}
