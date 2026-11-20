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
mod host;
mod jev_cli;
mod project;
mod register;
mod server;
mod setup_cli;
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
        /// The work item's id.
        item: String,
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
        /// The report's format: md, json or sarif.
        #[arg(long, default_value = "md", requires = "report")]
        format: String,
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

/// `devflow attack <item> --report <run>`: the run's report in `format`,
/// written beside it with its drafts, and printed.
fn reporting(root: &std::path::Path, item: &str, run: &str, format: &str) -> ExitCode {
    use devflow_engine::attack_report::{self, Format};
    let Some(format) = Format::of(format) else {
        eprintln!("devflow attack: --format is md, json or sarif");
        return ExitCode::FAILURE;
    };
    let project = project::Project::at(root);
    let runs = project.runs();
    let Some(at) = runs.found(item, Some(run), devflow_engine::attack::REPORT) else {
        eprintln!("devflow attack: run {run} of {item} has no attack report");
        return ExitCode::FAILURE;
    };
    let Some(report) = flow::json_at(&at) else {
        eprintln!("devflow attack: {} does not read", at.display());
        return ExitCode::FAILURE;
    };
    let folder = at.parent().unwrap_or(&at);
    if let Err(why) = attack_report::written(folder, &report) {
        eprintln!("devflow attack: {why}");
        return ExitCode::FAILURE;
    }
    let payloads = attack_report::payloads(folder, &report);
    let said = match format {
        Format::Markdown => attack_report::markdown(&report, &payloads),
        Format::Json => serde_json::to_string_pretty(&attack_report::json_of(&report, &payloads))
            .unwrap_or_default(),
        Format::Sarif => serde_json::to_string_pretty(&attack_report::sarif(&report, &payloads))
            .unwrap_or_default(),
    };
    println!("{said}");
    ExitCode::SUCCESS
}

/// `devflow attack`: the attack tool's answer, printed as JSON.
fn attacking(
    root: &std::path::Path,
    item: &str,
    base: Option<&str>,
    prove: Option<&str>,
) -> ExitCode {
    let server = server::Server::new(root);
    let mut asked = serde_json::json!({ "item": item });
    if let Some(base) = base {
        asked["base"] = serde_json::json!(base);
    }
    if let Some(run) = prove {
        asked["run"] = serde_json::json!(run);
        asked["prove"] = serde_json::json!(true);
    }
    match flow::attack::attack(&server, asked) {
        Ok(said) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&said).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("devflow attack: {why}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let root = cli.root.unwrap_or_else(|| PathBuf::from("."));
    match cli.command {
        Command::Mcp => {
            update::on_load();
            ExitCode::from(server::serve(&root) as u8)
        }
        Command::Version { json } => version(json),
        Command::Update { check, json } => update::command(check, json),
        Command::Host => host::run(&root),
        Command::Persona {
            action: Personas::Show { name },
        } => persona_show(&root, &name),
        Command::Payloads { action } => payloads(&root, action),
        Command::Status { attack: false } => status(&root),
        Command::Status { attack: true } => attack_status(&root),
        Command::Attack {
            item,
            report: Some(run),
            format,
            ..
        } => reporting(&root, &item, &run, &format),
        Command::Attack {
            item, base, prove, ..
        } => attacking(&root, &item, base.as_deref(), prove.as_deref()),
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

fn version(json: bool) -> ExitCode {
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

/// `devflow payloads`: the repertoire, its tables, and keeping a case.
fn payloads(root: &std::path::Path, action: Payloads) -> ExitCode {
    use devflow_engine::payloads;
    let failed = |why: String| {
        eprintln!("devflow payloads: {why}");
        ExitCode::FAILURE
    };
    let project = project::Project::at(root);
    match action {
        Payloads::List => {
            for name in payloads::names() {
                match payloads::class(&project.root, name) {
                    Ok(class) => println!("{name}\t{} cases\t{}", class.cases.len(), class.about),
                    Err(why) => return failed(why),
                }
            }
            ExitCode::SUCCESS
        }
        Payloads::Table { class, runner } => {
            let Some(runner) = payloads::Runner::of(&runner) else {
                return failed("--runner is jest, vitest, go or pytest".to_owned());
            };
            match payloads::class(&project.root, &class) {
                Ok(class) => {
                    print!("{}", payloads::table(&class, runner));
                    ExitCode::SUCCESS
                }
                Err(why) => failed(why),
            }
        }
        Payloads::Add { item, case, run } => {
            let runs = project.runs();
            let found = match run.as_deref() {
                Some(run) => runs.found(&item, Some(run), devflow_engine::attack::REPORT),
                None => runs
                    .newest_with(&item, devflow_engine::attack::REPORT)
                    .map(|(_, at)| at),
            };
            let Some((at, report)) =
                found.and_then(|at| flow::json_at(&at).map(|report| (at, report)))
            else {
                return failed(format!("{item} has no attack report to take a case from"));
            };
            // A report the repository carries never proposes a case.
            let relative = at
                .strip_prefix(&project.root)
                .ok()
                .map(|rest| rest.display().to_string());
            if let Some(relative) = relative {
                match devflow_engine::git::tracked(&project.root, &relative) {
                    Ok(false) => {}
                    Ok(true) => {
                        return failed(format!(
                            "{relative} is part of the repository: a report it carries proposes nothing"
                        ))
                    }
                    Err(why) => return failed(format!("{relative}: {why}")),
                }
            }
            println!("from: {}", at.display());
            let Some(proposed) = report["proposed_cases"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|one| one["id"] == case.as_str())
                .cloned()
            else {
                return failed(format!("the attack report proposes no case `{case}`"));
            };
            let class = proposed["class"].as_str().unwrap_or_default();
            println!(
                "class: {class}\ninput: {}\nwant: {}\nwhy: {}",
                serde_json::to_string(&proposed["input"]).unwrap_or_default(),
                proposed["want"].as_str().unwrap_or_default(),
                serde_json::to_string(&proposed["why"]).unwrap_or_default()
            );
            let question = format!("Keep it in {}?", payloads::kept_path(&project.root, class));
            match cli::confirmed(&question) {
                Ok(true) => match payloads::keep(&project.root, &proposed) {
                    Ok(at) => {
                        println!("kept in {at}");
                        ExitCode::SUCCESS
                    }
                    Err(why) => failed(why),
                },
                Ok(false) => {
                    println!("not kept");
                    ExitCode::SUCCESS
                }
                Err(why) => failed(why),
            }
        }
    }
}

/// `devflow persona show <name>`: the effective persona and what it was read
/// from.
fn persona_show(root: &std::path::Path, name: &str) -> ExitCode {
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

/// `devflow status --attack`: the project's attack numbers, as JSON.
fn attack_status(root: &std::path::Path) -> ExitCode {
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
