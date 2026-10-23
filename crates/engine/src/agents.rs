//! One reviewer's turn, headless, on whichever agent CLI the person set up —
//! Claude Code, Codex, Cursor, Gemini or OpenCode — under its own sign-in and
//! subscription, read only, and answered as text.
//!
//! Each CLI is asked the way its print mode takes a prompt and says what it
//! wrote; the review's packet is in the prompt, and what the review is about
//! is in the environment, never in a shell line: nothing here runs a shell.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

/// One agent CLI a reviewer runs on headless: how it is started, how its
/// print mode takes a prompt, and how its answer is read.
pub trait ReviewAgent: Sync {
    /// The name devflow.yaml uses.
    fn id(&self) -> &'static str;
    /// The program to run.
    fn program(&self) -> &'static str;
    /// The arguments after the program.
    fn argv(&self, model: Option<&str>, prompt: &str) -> Vec<String>;
    /// Whether the prompt goes on stdin rather than in the arguments.
    fn on_stdin(&self) -> bool;
    /// The text it answered, and its cost when it says one.
    fn answer_of(&self, stdout: &str) -> Result<(String, Option<f64>), String>;
    /// Whether a failed run's output says it is not signed in.
    fn signed_out(&self, said: &str) -> bool {
        signed_out(said)
    }
}

/// The agent CLIs a review runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cli {
    Claude,
    Codex,
    Cursor,
    Gemini,
    OpenCode,
}

impl Cli {
    pub const ALL: [Cli; 5] = [
        Cli::Claude,
        Cli::Codex,
        Cli::Cursor,
        Cli::Gemini,
        Cli::OpenCode,
    ];

    /// By the name devflow.yaml and the agents' list use.
    pub fn of(name: &str) -> Option<Cli> {
        Cli::ALL.into_iter().find(|cli| cli.id() == name)
    }

    pub fn id(self) -> &'static str {
        match self {
            Cli::Claude => "claude",
            Cli::Codex => "codex",
            Cli::Cursor => "cursor",
            Cli::Gemini => "gemini",
            Cli::OpenCode => "opencode",
        }
    }

    /// The program to run.
    pub fn program(self) -> &'static str {
        match self {
            Cli::Cursor => "cursor-agent",
            other => other.id(),
        }
    }
}

impl ReviewAgent for Cli {
    fn id(&self) -> &'static str {
        Cli::id(*self)
    }

    fn program(&self) -> &'static str {
        Cli::program(*self)
    }

    fn argv(&self, model: Option<&str>, prompt: &str) -> Vec<String> {
        argv(*self, model, prompt)
    }

    fn on_stdin(&self) -> bool {
        on_stdin(*self)
    }

    fn answer_of(&self, stdout: &str) -> Result<(String, Option<f64>), String> {
        answer_of(*self, stdout)
    }
}

/// What one review is run with.
pub struct Review<'a> {
    pub agent: &'a dyn ReviewAgent,
    /// [`ReviewAgent::program`], or another build of the same CLI.
    pub program: &'a str,
    pub prompt: &'a str,
    pub cwd: &'a Path,
    pub model: Option<&'a str>,
    /// What the review is about, as variables.
    pub env: &'a [(String, String)],
    pub deadline: Duration,
}

/// What a reviewer wrote, and what it cost when its CLI says.
#[derive(Debug, Clone, PartialEq)]
pub struct Reviewed {
    pub text: String,
    pub cost_usd: Option<f64>,
    pub duration_ms: u64,
}

/// Why a reviewer gave no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unreviewed {
    /// The CLI is not installed, or not on PATH.
    Missing,
    /// It ran and said it is not signed in.
    SignedOut(String),
    Failed(String),
    TimedOut,
}

impl Unreviewed {
    pub fn reason(&self) -> String {
        match self {
            Unreviewed::Missing => "not installed".to_owned(),
            Unreviewed::SignedOut(said) => format!("not signed in: {said}"),
            Unreviewed::Failed(why) => why.clone(),
            Unreviewed::TimedOut => "gave no answer in the time the review had".to_owned(),
        }
    }
}

/// The tools a Claude Code reviewer may use without asking: reading, and
/// git's reading commands. Everything else is refused in print mode.
const CLAUDE_READS: [&str; 6] = [
    "Read",
    "Grep",
    "Glob",
    "Bash(git diff:*)",
    "Bash(git log:*)",
    "Bash(git show:*)",
];

/// The most turns a Claude Code reviewer takes: generous for reading a diff,
/// a stop for one wandering the repository at the person's cost.
pub const CLAUDE_TURNS: u32 = 60;

/// The arguments after the program. A CLI that reads its prompt from stdin
/// gets none of it here; the others get it last.
pub fn argv(cli: Cli, model: Option<&str>, prompt: &str) -> Vec<String> {
    let mut argv: Vec<String> = match cli {
        Cli::Claude => vec!["-p".into(), "--output-format".into(), "json".into()],
        // Codex's read-only sandbox: it may read and run git, and write nothing.
        Cli::Codex => vec![
            "exec".into(),
            "--sandbox".into(),
            "read-only".into(),
            "--color".into(),
            "never".into(),
        ],
        Cli::Cursor => vec!["-p".into(), "--output-format".into(), "json".into()],
        Cli::Gemini => vec!["--output-format".into(), "json".into()],
        // OpenCode's `plan` agent may read and edits nothing.
        Cli::OpenCode => vec!["run".into(), "--agent".into(), "plan".into()],
    };
    if let Some(model) = model {
        argv.push("--model".into());
        argv.push(model.to_owned());
    }
    match cli {
        Cli::Claude => {
            // None of the person's MCP servers: a reviewer reads files and git.
            argv.push("--strict-mcp-config".into());
            argv.push("--max-turns".into());
            argv.push(CLAUDE_TURNS.to_string());
            argv.push("--allowedTools".into());
            argv.extend(CLAUDE_READS.iter().map(|tool| (*tool).to_owned()));
        }
        // `-`: the prompt is on stdin.
        Cli::Codex => argv.push("-".into()),
        Cli::Cursor => argv.push(prompt.to_owned()),
        Cli::Gemini => {
            argv.push("-p".into());
            argv.push(prompt.to_owned());
        }
        Cli::OpenCode => {
            argv.push("--".into());
            argv.push(prompt.to_owned());
        }
    }
    argv
}

/// Whether the prompt goes on stdin rather than in the arguments.
pub fn on_stdin(cli: Cli) -> bool {
    matches!(cli, Cli::Claude | Cli::Codex)
}

/// The text a CLI answered, and its cost when it says one: Claude Code and
/// Cursor print a result object, Gemini a response object, Codex and
/// OpenCode their last message as it is. Output in none of these shapes is
/// taken as the text.
pub fn answer_of(cli: Cli, stdout: &str) -> Result<(String, Option<f64>), String> {
    let printed: Option<Value> = serde_json::from_str(stdout.trim()).ok().map(last_result);
    let Some(printed) = printed.filter(|_| !matches!(cli, Cli::Codex | Cli::OpenCode)) else {
        return Ok((stdout.to_owned(), None));
    };
    if printed.is_null() {
        return Err("its CLI printed no result".to_owned());
    }
    let field = if cli == Cli::Gemini {
        "response"
    } else {
        "result"
    };
    if printed.get("subtype").and_then(Value::as_str) == Some("error_max_turns") {
        return Err(format!(
            "it used its {CLAUDE_TURNS} turns without answering"
        ));
    }
    if printed.get("is_error").and_then(Value::as_bool) == Some(true) {
        let said = printed.get(field).and_then(Value::as_str).unwrap_or("");
        return Err(format!("its CLI reported an error: {}", first_line(said)));
    }
    if let Some(error) = printed.get("error").filter(|error| !error.is_null()) {
        let said = error
            .get("message")
            .and_then(Value::as_str)
            .map_or_else(|| error.to_string(), str::to_owned);
        return Err(format!("its CLI reported an error: {}", first_line(&said)));
    }
    let text = printed
        .get(field)
        .and_then(Value::as_str)
        .map_or_else(|| stdout.to_owned(), str::to_owned);
    let cost = printed
        .get("total_cost_usd")
        .or_else(|| printed.get("cost_usd"))
        .and_then(Value::as_f64);
    Ok((text, cost))
}

/// The result object of what a CLI printed. With `"verbose": true` in the
/// person's settings, Claude Code prints every event of the run as an array
/// instead of the result alone: the result is its last `type: result`.
fn last_result(printed: Value) -> Value {
    match printed {
        Value::Array(events) => events
            .into_iter()
            .rev()
            .find(|event| event.get("type").and_then(Value::as_str) == Some("result"))
            .unwrap_or(Value::Null),
        printed => printed,
    }
}

/// What the CLIs say when nobody is signed in to them.
const SIGNED_OUT: [&str; 9] = [
    "not logged in",
    "please log in",
    "please login",
    "login required",
    "not authenticated",
    "unauthenticated",
    "invalid api key",
    "/login",
    "run `codex login`",
];

/// Whether a failed run's output says the CLI is not signed in.
pub fn signed_out(said: &str) -> bool {
    let said = said.to_lowercase();
    SIGNED_OUT.iter().any(|words| said.contains(words))
}

fn first_line(text: &str) -> String {
    let line = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    line.chars().take(200).collect()
}

/// The most of a reviewer's output read: a findings object, not a log.
const MOST_OUTPUT: u64 = 4 * 1024 * 1024;

fn drained(from: Option<impl Read + Send + 'static>) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut text = String::new();
        if let Some(from) = from {
            let _ = from.take(MOST_OUTPUT).read_to_string(&mut text);
        }
        text
    })
}

/// How often a running review is looked at.
const EVERY: Duration = Duration::from_millis(100);

fn waited(child: &mut Child, deadline: Instant) -> Option<std::process::ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(EVERY),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// Runs one review to its answer, or says why there is none. Stopped at
/// its deadline: a reviewer that hangs costs the review one reviewer.
pub fn review(asked: &Review<'_>) -> Result<Reviewed, Unreviewed> {
    let began = Instant::now();
    let agent = asked.agent;
    let mut child = crate::env::command(asked.program)
        .args(agent.argv(asked.model, asked.prompt))
        .current_dir(asked.cwd)
        .envs(asked.env.iter().map(|(key, value)| (key, value)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| match err.kind() {
            std::io::ErrorKind::NotFound => Unreviewed::Missing,
            _ => Unreviewed::Failed(format!("could not start: {err}")),
        })?;
    let stdin = child.stdin.take();
    let prompt = agent.on_stdin().then(|| asked.prompt.to_owned());
    // Its own thread: a prompt past the pipe's buffer would block until the
    // CLI reads it, and the CLI may read it only after we read its output.
    let writing = std::thread::spawn(move || {
        if let (Some(mut stdin), Some(prompt)) = (stdin, prompt) {
            let _ = stdin.write_all(prompt.as_bytes());
        }
    });
    let stdout = drained(child.stdout.take());
    let stderr = drained(child.stderr.take());
    let Some(status) = waited(&mut child, began + asked.deadline) else {
        return Err(Unreviewed::TimedOut);
    };
    let _ = writing.join();
    let stdout = stdout.join().unwrap_or_default();
    let stderr = stderr.join().unwrap_or_default();
    let duration_ms = began.elapsed().as_millis() as u64;
    if !status.success() {
        let said = format!("{stderr}\n{stdout}");
        if agent.signed_out(&said) {
            return Err(Unreviewed::SignedOut(first_line(&said)));
        }
        return Err(Unreviewed::Failed(format!(
            "ended with {status}: {}",
            first_line(&said)
        )));
    }
    let (text, cost_usd) = agent.answer_of(&stdout).map_err(|why| {
        if agent.signed_out(&why) {
            Unreviewed::SignedOut(why)
        } else {
            Unreviewed::Failed(why)
        }
    })?;
    Ok(Reviewed {
        text,
        cost_usd,
        duration_ms,
    })
}

#[cfg(test)]
#[path = "agents_tests.rs"]
mod tests;
