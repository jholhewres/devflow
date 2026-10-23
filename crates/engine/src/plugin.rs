//! The Claude Code plugin's files, made from the flow: a skill per stage
//! that sends the agent to the project's own (`/devflow:<stage>`), the
//! person's commands, the reviewer personas as subagents, and the hooks that
//! hold a turn at the gate and give a session its work item.
//!
//! `cargo xtask plugin-sync` writes them at the repository's root, where the
//! plugin lives, and its `--check` fails when they drift from the flow.

use serde_json::{json, Map, Value};

use crate::skills;

/// The plugin's name: its skills are `/devflow:<stage>`.
pub const NAME: &str = "devflow";
/// The binary the hooks run, found on `PATH` as the MCP server is.
pub const BIN: &str = "devflow";
/// A stop may wait on Decisions; the gate answers well inside this.
pub const GATE_WAITS: u64 = 60;
/// A session's start reads its work item from the project's files.
pub const CONTEXT_WAITS: u64 = 10;

/// The reviewer personas, as subagents a review hands one packet each.
pub const PERSONAS: [(&str, &str); 4] = [
    (
        "devflow-spec",
        include_str!("../../../flow/personas/devflow-spec.md"),
    ),
    (
        "devflow-standards",
        include_str!("../../../flow/personas/devflow-standards.md"),
    ),
    (
        "devflow-security",
        include_str!("../../../flow/personas/devflow-security.md"),
    ),
    (
        "devflow-all",
        include_str!("../../../flow/personas/devflow-all.md"),
    ),
];

/// The line a hook runs for `event`.
pub fn hook_command(event: &str, agent: &str) -> String {
    format!("{BIN} hook {event} --agent {agent}")
}

/// The hooks, in the `hooks.json` shape Claude Code reads.
pub fn hooks(agent: &str) -> Value {
    let handler = |event: &str, timeout: u64| json!([{ "hooks": [{ "type": "command", "command": hook_command(event, agent), "timeout": timeout }] }]);
    let mut events = Map::new();
    events.insert("Stop".to_owned(), handler("stop", GATE_WAITS));
    events.insert(
        "SubagentStop".to_owned(),
        handler("subagent-stop", GATE_WAITS),
    );
    events.insert(
        "SessionStart".to_owned(),
        handler("session-start", CONTEXT_WAITS),
    );
    json!({
        "description": "devflow's gate at each stop, and the session's work item at its start",
        "hooks": events,
    })
}

/// A skill that sends the agent to the project's own: the MCP server
/// resolves the project's, a team's, the person's or the built-in one, so
/// the plugin stays one folder for every project.
fn pointer(name: &str, skill: &str, description: &str) -> String {
    format!(
        "---\nname: {name}\ndescription: {description}\n---\n\n\
         Call devflow's `skill` tool with `{{ \"name\": \"{skill}\" }}` and follow the skill it \
         returns: it is this project's own when the project has one. When devflow's tools are \
         not there, read the resource `{}` from the devflow server instead.\n",
        skills::uri(skill)
    )
}

/// One description on one line, as frontmatter takes it.
fn one_line(text: &str) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    serde_json::to_string(&flat).unwrap_or_default()
}

/// A command: what it is for, and what the agent does with it.
fn command(description: &str, hint: Option<&str>, body: &str) -> String {
    let mut text = format!("---\ndescription: {}\n", one_line(description));
    if let Some(hint) = hint {
        text.push_str(&format!("argument-hint: {}\n", one_line(hint)));
    }
    text.push_str("---\n\n");
    text.push_str(body);
    if !body.ends_with('\n') {
        text.push('\n');
    }
    text
}

/// The person's commands, `/devflow:<name>`, apart from the stages' skills.
pub fn commands() -> Vec<(&'static str, String)> {
    vec![
        (
            "status",
            command(
                "devflow in this project: its state, what was detected and what comes next",
                None,
                "Call devflow's `status` tool and tell me, in a few lines, the project's state, \
                 the checks it found or recommends, anything left open, and the step that comes \
                 next. If devflow is set up but off, say the command I run to switch it on.",
            ),
        ),
        (
            "items",
            command(
                "The project's work items and where each stands",
                Some("[open|doing|done]"),
                "Call devflow's `items` tool (with `state` set to \"$ARGUMENTS\" when I gave \
                 one) and list the items as a short table: id, title, state, what still blocks \
                 it. Name the one this session works on.",
            ),
        ),
        (
            "next",
            command(
                "The next work item of an epic, by its blockers",
                Some("<epic>"),
                "Call devflow's `next` tool with `epic` \"$ARGUMENTS\" and tell me which item \
                 comes next and why. If it can start, offer to `start` it and follow the flow \
                 through `gate`; if it waits on me, say what I have to check.",
            ),
        ),
        (
            "gate",
            command(
                "Whether a work item may be called done, on its evidence",
                Some("[item]"),
                "Call devflow's `gate` tool with `item` \"$ARGUMENTS\" (when I gave none, the \
                 item `items` names as current). Say passed or failed, and for each thing \
                 missing, the stage that fixes it.",
            ),
        ),
        (
            "pr",
            command(
                "Review a pull request with devflow's reviewers, without a work item",
                Some("<number or URL>"),
                "Follow devflow's review skill (`skill` devflow-review) to review pull request \
                 $ARGUMENTS on demand: call `review` with `pr`, review what is pending yourself, \
                 and show me the verdict and the findings. Draft it with `publish` and post it \
                 only after my explicit yes to that draft.",
            ),
        ),
    ]
}

/// A persona as Claude Code reads a subagent: its file as devflow ships it.
pub fn agents() -> Vec<(&'static str, &'static str)> {
    PERSONAS.to_vec()
}

/// Every file of the plugin, by its path at the repository's root.
pub fn claude() -> Vec<(String, String)> {
    let mut files = vec![("hooks/hooks.json".to_owned(), pretty(&hooks("claude")))];
    for (skill, stage, description) in skills::described() {
        let short = stage.unwrap_or("setup");
        files.push((
            format!("skills/{short}/SKILL.md"),
            pointer(short, skill, &one_line(&description)),
        ));
    }
    for (name, text) in commands() {
        files.push((format!("commands/{name}.md"), text));
    }
    for (name, text) in agents() {
        files.push((format!("agents/{name}.md"), text.to_owned()));
    }
    files
}

/// What an agent reads where the tool takes no plugin: GEMINI.md, a
/// project's AGENTS.md for Codex, a Cursor rule.
pub const CONTEXT: &str = "\
# devflow

This project may use devflow: an engineering flow of briefing, context, plan,
execution, review and completion, in which work is done only when its
evidence says so — its checks green after the last change, each acceptance
criterion proven by a test or a proof file, a review that blocks nothing.
Its tools come from the `devflow` MCP server.

- Call `status` first: the project's state and the step that comes next.
- Before each stage, call `skill` with `devflow-<stage>` (briefing, context,
  plan, execution, review, completion) and follow the skill it returns.
- Work items are Markdown files in the project's devflow folder: `items`
  lists them, `item` reads or makes one, `start` picks the one you work on.
- An item is done when `gate` passes: run its checks with `evidence`, review
  it with `review`, then `gate`, then `finish`.
- What only the person decides — switching devflow on, Decisions in enforce,
  a team layer's command — is a terminal command the tools name; a brief, a
  plan or a published review waits for their explicit yes in the conversation.
";

/// The context files outside the plugin's folders, by path at the root.
pub fn contexts() -> Vec<(String, String)> {
    let rule = format!(
        "---\ndescription: devflow, the evidence-gated engineering flow, through its MCP server\nalwaysApply: true\n---\n\n{}",
        CONTEXT.trim_start_matches("# devflow\n\n")
    );
    vec![
        ("GEMINI.md".to_owned(), CONTEXT.to_owned()),
        (
            "integrations/codex/AGENTS.md".to_owned(),
            CONTEXT.to_owned(),
        ),
        ("integrations/cursor/rules/devflow.mdc".to_owned(), rule),
    ]
}

fn pretty(value: &Value) -> String {
    format!(
        "{}\n",
        serde_json::to_string_pretty(value).unwrap_or_default()
    )
}

#[cfg(test)]
#[path = "plugin_tests.rs"]
mod tests;
