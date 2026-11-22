//! `devflow`: the MCP server agent CLIs start, and the few commands a person
//! runs to set it up and check on it.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod attack_cli;
mod cli;
mod consent;
mod credentials;
mod decisions;
mod doctor;
mod flow;
mod hook;
mod host;
mod jev_cli;
mod payloads_cli;
mod person;
mod project;
mod reach;
mod ready;
mod register;
mod register_cli;
mod server;
mod setup_cli;
mod status_cli;
mod tools;
mod update;

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
    /// Serve MCP over stdio. Agent CLIs run this; a person does not. Each
    /// start installs a newer release in the background, unless
    /// DEVFLOW_NO_UPDATE=1.
    Mcp,
    /// This binary's version and the host protocols it speaks.
    Version {
        /// As JSON: {"version", "protocols"}.
        #[arg(long)]
        json: bool,
    },
    /// Install the latest release over this binary now, and bring the
    /// Claude Code plugin to it. Never asks anything.
    Update {
        /// Say whether a newer release is out, and change nothing.
        #[arg(long)]
        check: bool,
        /// One JSON line: {"updated", "from", "to"}, or {"error"}.
        #[arg(long)]
        json: bool,
    },
    /// Serve one call from a host app (devpit) over stdio JSON-RPC: the
    /// project's devflow.yaml and the flow's tools. A host runs this.
    Host,
    /// Say which configuration applies to the project, if any.
    Status {
        /// The attack's numbers for the project: its runs, what they
        /// confirmed and cost, what the review missed, and the run mode
        /// they suggest.
        #[arg(long)]
        attack: bool,
    },
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
    /// The attack stage on a work item: devflow-security tries to exploit its
    /// change headless and keeps attack.json in a run of the item.
    Attack {
        /// The work item's id; or `promote`, then the item or range and the
        /// hypothesis whose exploit is copied into the repository.
        #[arg(required_unless_present = "range")]
        item: Option<String>,
        /// With `promote`: the item or range, then the hypothesis.
        #[arg(num_args = 0..=2)]
        promote: Vec<String>,
        /// With `promote`: the attack run; the newest when not said.
        #[arg(long, value_name = "RUN", conflicts_with_all = ["prove", "report"])]
        run: Option<String>,
        /// Where the diff starts, when not where the item started.
        #[arg(long)]
        base: Option<String>,
        /// Prove the confirmed exploits of this attack run: red at the
        /// commit each was confirmed on, green at HEAD.
        #[arg(long, value_name = "RUN")]
        prove: Option<String>,
        /// Print this attack run's report, written beside it with its issue
        /// drafts, instead of attacking.
        #[arg(long, value_name = "RUN", conflicts_with = "prove")]
        report: Option<String>,
        /// A flow of the project's workspace manifest to attack with it.
        #[arg(long)]
        flow: Option<String>,
        /// The report's format: md, json or sarif.
        #[arg(long, default_value = "md", requires = "report")]
        format: String,
        /// Attack a release range, `A..B`, headless for CI: SARIF and JUnit
        /// are written, and the exit code is 1 when a confirmed exploit is
        /// in review.block_on, 2 when the attack could not run.
        #[arg(long, value_name = "A..B", conflicts_with_all = ["item", "base", "prove", "report", "flow", "run"])]
        range: Option<String>,
        /// With `--range`: where the SARIF goes.
        #[arg(
            long,
            value_name = "FILE",
            default_value = "devflow-attack.sarif",
            requires = "range"
        )]
        sarif: PathBuf,
        /// With `--range`: where the JUnit goes.
        #[arg(
            long,
            value_name = "FILE",
            default_value = "devflow-attack.junit.xml",
            requires = "range"
        )]
        junit: PathBuf,
    },
    /// The reviewer personas as this project reads them.
    Persona {
        #[command(subcommand)]
        action: Personas,
    },
    /// The attack's payload repertoire: generic cases by class, as test
    /// tables, and the project's own.
    Payloads {
        #[command(subcommand)]
        action: Payloads,
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
    Set {
        path: String,
        /// The value, which may start with `-`: devflow says why it is refused.
        #[arg(allow_hyphen_values = true)]
        value: String,
    },
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
enum Payloads {
    /// The classes, with their count of cases.
    List,
    /// Print a class's test table for a runner: jest, vitest, go or pytest.
    Table {
        class: String,
        #[arg(long, default_value = "jest")]
        runner: String,
    },
    /// Keep a case an attack proposed in the project's own cases, after your
    /// yes on a terminal.
    Add {
        item: String,
        case: String,
        /// The attack run that proposed it; the newest when not said.
        #[arg(long)]
        run: Option<String>,
    },
}

#[derive(Subcommand)]
enum Personas {
    /// Print a persona as a reader reads it here: its text from the layers,
    /// then the project's overlay, with devflow's version and each digest.
    Show { name: String },
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
        Command::Mcp => {
            update::on_load();
            ExitCode::from(server::serve(&root) as u8)
        }
        Command::Version { json } => status_cli::version(json),
        Command::Update { check, json } => update::command(check, json),
        Command::Host => host::run(&root),
        Command::Persona {
            action: Personas::Show { name },
        } => status_cli::persona_show(&root, &name),
        Command::Payloads { action } => payloads_cli::payloads(&root, action),
        Command::Status { attack: false } => status_cli::status(&root),
        Command::Status { attack: true } => status_cli::attack_status(&root),
        Command::Attack {
            range: Some(range),
            sarif,
            junit,
            ..
        } => attack_cli::ranging(&root, &range, &sarif, &junit),
        Command::Attack { item: None, .. } => {
            eprintln!("devflow attack <item>, or --range A..B");
            ExitCode::FAILURE
        }
        Command::Attack {
            item: Some(item),
            promote,
            run,
            ..
        } if item == "promote" => match promote.as_slice() {
            [subject, hypothesis] => {
                attack_cli::promoting(&root, subject, hypothesis, run.as_deref())
            }
            _ => {
                eprintln!("devflow attack promote <item or range> <hypothesis> [--run RUN]");
                ExitCode::FAILURE
            }
        },
        Command::Attack { promote, run, .. } if !promote.is_empty() || run.is_some() => {
            eprintln!("devflow attack takes one item; `--run` and two names are for `devflow attack promote`");
            ExitCode::FAILURE
        }
        Command::Attack {
            item: Some(item),
            report: Some(run),
            format,
            ..
        } => attack_cli::reporting(&root, &item, &run, &format),
        Command::Attack {
            item: Some(item),
            base,
            prove,
            flow,
            ..
        } => attack_cli::attacking(
            &root,
            &item,
            base.as_deref(),
            prove.as_deref(),
            flow.as_deref(),
        ),
        Command::Setup(how) => setup_cli::run(&root, &how),
        Command::Doctor => doctor::run(&root),
        Command::Register(how) => register_cli::registering(&how, true),
        Command::Unregister(how) => register_cli::registering(&how, false),
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
