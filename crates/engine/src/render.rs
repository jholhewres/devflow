//! A configuration written out as devflow.yaml, with the comments a person
//! needs to edit it by hand. The one layout devpit writes for each version;
//! reading it back gives the same configuration.

use std::fmt::Write;

use crate::config::{Approved, Check, Config, Stage, StageGate, Step, E2E_DIR, V1};

/// The text of `config`, commented.
pub fn render(config: &Config) -> String {
    let mut out = String::new();
    out.push_str(
        "# Devflow: briefing → context → plan → execution → review → completion,\n\
         # served by devflow's MCP. This file is the source of truth: devflow edits\n\
         # it and never commits it.\n",
    );
    let _ = writeln!(out, "version: {}", config.version);
    out.push_str(
        "\n# Switched on by the person's click with `devflow config set`, never by an agent.\n",
    );
    let _ = writeln!(out, "enabled: {}", config.enabled);
    if config.version == V1 {
        stages_v1(&mut out, config);
    } else {
        extends(&mut out, config);
        stages_v2(&mut out, config);
    }
    review(&mut out, config);
    if config.version != V1 && !config.locked.is_empty() {
        out.push_str("\n# Fields a project extending this file may not change.\nlocked:\n");
        for path in &config.locked {
            let _ = writeln!(out, "  - {}", scalar(path));
        }
    }
    out
}

fn checks(out: &mut String, indent: &str, checks: &[Check]) {
    if checks.is_empty() {
        let _ = writeln!(out, "{indent}checks: []");
        return;
    }
    let _ = writeln!(
        out,
        "{indent}# Run by devflow from the project's root for the evidence on the work item.\n\
         {indent}# report: junit | vitest | jest | cargo | none\n\
         {indent}checks:"
    );
    for check in checks {
        let _ = writeln!(out, "{indent}  - name: {}", scalar(&check.name));
        let _ = writeln!(out, "{indent}    run: {}", scalar(&check.run));
        let _ = writeln!(out, "{indent}    report: {}", check.report.word());
        if !check.evidence.is_empty() {
            let kept: Vec<&str> = check.evidence.iter().map(|one| one.word()).collect();
            let _ = writeln!(out, "{indent}    evidence: [{}]", kept.join(", "));
        }
        if let Some(requires) = &check.requires {
            let _ = writeln!(out, "{indent}    requires: {}", scalar(requires));
        }
        if let Some(exclusive) = &check.exclusive {
            let _ = writeln!(out, "{indent}    exclusive: {}", scalar(exclusive));
        }
    }
}

/// Where the specs go, written only when it is not where they go anyway.
fn e2e_dir(out: &mut String, dir: &str) {
    if dir != E2E_DIR {
        let _ = writeln!(out, "    e2e_dir: {}", scalar(dir));
    }
}

fn stages_v1(out: &mut String, config: &Config) {
    let stages = &config.stages;
    out.push_str("\nstages:\n");
    out.push_str("  # approve: person stops for the person's yes; none goes on.\n");
    approved(out, "briefing", &stages.briefing);
    plain(out, "context", &stages.context);
    approved(out, "plan", &stages.plan);
    let execution = &stages.execution;
    let _ = writeln!(out, "  execution:\n    enabled: {}", execution.enabled);
    checks(out, "    ", &execution.checks);
    e2e_dir(out, &execution.e2e_dir);
    plain(out, "review", &stages.review);
    let _ = writeln!(
        out,
        "  completion:\n    enabled: {}\n    gate: {}",
        stages.completion.enabled,
        scalar(&stages.completion.gate)
    );
}

fn extends(out: &mut String, config: &Config) {
    if config.extends.is_empty() {
        return;
    }
    out.push_str(
        "\n# Team or company layers, each at a fixed ref. devflow.lock pins the\n\
         # commit the person approved; a new ref applies once they approve it.\n\
         extends:\n",
    );
    for layer in &config.extends {
        let _ = writeln!(out, "  - git: {}", scalar(&layer.git));
        let _ = writeln!(out, "    ref: {}", scalar(&layer.reference));
    }
}

fn stages_v2(out: &mut String, config: &Config) {
    out.push_str(
        "\n# The stages, in order. uses: builtin/<stage> is devflow's own; an own\n\
         # stage uses project/<skill> (.devflow/skills/), personal/<skill>,\n\
         # skills/<name> (a skill already installed for the agent CLIs) or\n\
         # <team>/<skill>, with a gate: { command: … } or { rubric: … }.\n\
         # approve: person stops for the person's yes; none goes on.\n\
         stages:\n",
    );
    if config.flow.is_empty() {
        out.push_str("  []\n");
    }
    for step in &config.flow {
        let _ = writeln!(out, "  - uses: {}", scalar(&step.uses));
        let _ = writeln!(out, "    enabled: {}", config.is_on(step));
        stage_fields(out, config, step);
    }
}

fn stage_fields(out: &mut String, config: &Config, step: &Step) {
    let stages = &config.stages;
    match (step.builtin(), &step.own) {
        (Some("briefing"), _) => {
            let _ = writeln!(out, "    approve: {}", stages.briefing.approve.word());
        }
        (Some("plan"), _) => {
            let _ = writeln!(out, "    approve: {}", stages.plan.approve.word());
            if let Some(publish) = stages.plan.publish {
                let _ = writeln!(
                    out,
                    "    publish: {}   # board | jira | linear | github",
                    publish.word()
                );
            }
            if let Some(unblock_on) = stages.plan.unblock_on {
                let _ = writeln!(out, "    unblock_on: {}   # done | gate", unblock_on.word());
            }
        }
        (Some("execution"), _) => {
            checks(out, "    ", &stages.execution.checks);
            e2e_dir(out, &stages.execution.e2e_dir);
        }
        (Some("completion"), _) => {
            let _ = writeln!(out, "    gate: {}", scalar(&stages.completion.gate));
        }
        (None, Some(own)) => {
            if let Some(approve) = own.approve {
                let _ = writeln!(out, "    approve: {}", approve.word());
            }
            match &own.gate {
                Some(StageGate::Command(command)) => {
                    let _ = writeln!(out, "    gate: {{ command: {} }}", scalar(command));
                }
                Some(StageGate::Rubric(rubric)) => {
                    let _ = writeln!(out, "    gate: {{ rubric: {} }}", scalar(rubric));
                }
                None => {}
            }
        }
        _ => {}
    }
}

fn review(out: &mut String, config: &Config) {
    out.push_str(
        "\nreview:\n  # The agent CLI each persona runs in; a persona not listed is\n  \
         # reviewed by the session itself.\n",
    );
    if config.review.reviewers.is_empty() {
        out.push_str("  reviewers: []\n");
    } else {
        out.push_str("  reviewers:\n");
        for reviewer in &config.review.reviewers {
            let _ = writeln!(out, "    - agent: {}", reviewer.agent.word());
            let _ = writeln!(out, "      persona: {}", scalar(&reviewer.persona));
            if let Some(model) = &reviewer.model {
                let _ = writeln!(out, "      model: {}", scalar(model));
            }
        }
    }
    let severities: Vec<&str> = config
        .review
        .block_on
        .iter()
        .map(|one| one.word())
        .collect();
    let _ = writeln!(out, "  block_on: [{}]", severities.join(", "));
    out.push_str(
        "  # How several reviewers' findings become one: jev (Decisions, else a\n  \
         # model pass), agent (one model pass) or none (merged as they are).\n",
    );
    let _ = writeln!(out, "  consolidate: {}", config.review.consolidate.word());
    if let Some(scale) = &config.review.scale {
        out.push_str(
            "  # A diff of at most small_lines changed lines that touches no\n  \
             # sensitive path is read by one devflow-all reviewer.\n  \
             scale:\n",
        );
        let _ = writeln!(out, "    small_lines: {}", scale.small_lines);
        if scale.sensitive != crate::scale::Scale::default().sensitive {
            let globs: Vec<String> = scale.sensitive.iter().map(|one| scalar(one)).collect();
            let _ = writeln!(out, "    sensitive: [{}]", globs.join(", "));
        }
    }
    if config.review.verify != crate::config::Verify::Off {
        out.push_str(
            "  # The session runs each critical and high's PoC: advise asks it,\n  \
             # required also counts a high it did not confirm as medium.\n",
        );
        let _ = writeln!(out, "  verify: {}", config.review.verify.word());
    }

    out.push_str(
        "\n# Decisions (Jev) answers typed questions about the gates. shadow logs\n\
         # them; enforce blocks, and waits for the person's click in the app.\n\
         # It is sent findings, criteria with their evidence, the brief and the\n\
         # plan — never the diff — through the provider in Settings → Decisions\n\
         # (OpenRouter unless changed), with no retention and no training.\n\
         # rubrics: a stage's own rubric, from .devflow/rubrics/.\n\
         decisions:\n",
    );
    let decisions = &config.decisions;
    let _ = writeln!(
        out,
        "  use: {}\n  mode: {}",
        decisions.use_,
        decisions.mode.word()
    );
    if !decisions.rubrics.is_empty() {
        out.push_str("  rubrics:\n");
        for (stage, rubric) in &decisions.rubrics {
            let _ = writeln!(out, "    {stage}: {}", scalar(rubric));
        }
    }
}

fn plain(out: &mut String, name: &str, stage: &Stage) {
    let _ = writeln!(out, "  {name}:\n    enabled: {}", stage.enabled);
}

fn approved(out: &mut String, name: &str, stage: &Approved) {
    let _ = writeln!(
        out,
        "  {name}:\n    enabled: {}\n    approve: {}",
        stage.enabled,
        stage.approve.word()
    );
    if let Some(publish) = stage.publish {
        let _ = writeln!(out, "    publish: {}", publish.word());
    }
    if let Some(unblock_on) = stage.unblock_on {
        let _ = writeln!(out, "    unblock_on: {}", unblock_on.word());
    }
}
/// A string as YAML: plain when it reads back as the same string, double
/// quoted otherwise.
pub(crate) fn scalar(text: &str) -> String {
    if plain_enough(text) {
        return text.to_owned();
    }
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('"');
    for one in text.chars() {
        match one {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\n' => quoted.push_str("\\n"),
            '\t' => quoted.push_str("\\t"),
            one if one.is_control() => {
                let _ = write!(quoted, "\\u{:04x}", one as u32);
            }
            one => quoted.push(one),
        }
    }
    quoted.push('"');
    quoted
}

/// Whether `text` written bare reads back as itself and as a string.
fn plain_enough(text: &str) -> bool {
    let Some(first) = text.chars().next() else {
        return false;
    };
    let typed = matches!(
        text.to_ascii_lowercase().as_str(),
        "true" | "false" | "null" | "~" | "yes" | "no" | "on" | "off"
    ) || text.parse::<f64>().is_ok();
    !typed
        && (first.is_ascii_alphanumeric() || "./_$".contains(first))
        && !text.ends_with([' ', ':'])
        && !text.contains(": ")
        && !text.contains(" #")
        && text
            .chars()
            .all(|one| one.is_ascii_alphanumeric() || " ./_-=+@:$".contains(one))
}

#[cfg(test)]
#[path = "render_tests.rs"]
mod tests;
