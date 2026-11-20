//! A configuration written out as devflow.yaml, with the comments a person
//! needs to edit it by hand. The one layout devpit writes for each version;
//! reading it back gives the same configuration.

use std::fmt::Write;

use crate::config::{Approved, Attack, Budget, Check, Config, Stage, StageGate, Step, V1};
use crate::dialect::Dialect;

/// The text of `config`, commented.
pub fn render(config: &Config) -> String {
    render_in(&Dialect::DEVFLOW, config)
}

/// [`render`], its comments in `dialect`'s words.
pub fn render_in(dialect: &Dialect, config: &Config) -> String {
    let mut out = String::new();
    out.push_str(dialect.yaml_header);
    let _ = writeln!(out, "version: {}", config.version);
    out.push('\n');
    out.push_str(dialect.yaml_enabled);
    let _ = writeln!(out, "enabled: {}", config.enabled);
    if let Some(models) = config.models {
        out.push_str(
            "\n# The models preset: economy runs the work and the review small and an\n\
             # analysis large; quality runs everything large. A stage's own model wins.\n",
        );
        let _ = writeln!(out, "models: {}", models.word());
    }
    if config.version == V1 {
        stages_v1(dialect, &mut out, config);
    } else {
        extends(&mut out, config);
        stages_v2(dialect, &mut out, config);
    }
    review(dialect, &mut out, config);
    if !config.criteria.is_empty() {
        let _ = writeln!(
            out,
            "\n# Headings, besides `## Acceptance criteria`, whose checkboxes are a\n\
             # {}'s criteria.\ncriteria:\n  headings:",
            dialect.work_item
        );
        for heading in &config.criteria.headings {
            let _ = writeln!(out, "    - {}", scalar(heading));
        }
    }
    if !config.security.is_empty() {
        out.push_str(
            "\n# The project's own running instances an attack may send requests to:\n\
             # loopback, localhost, host.docker.internal or a docker service's name.\n\
             # Each is in force only once the person confirms it on a terminal with\n\
             # `devflow config set security.targets`.\n\
             security:\n",
        );
        if config.security.targets.is_empty() {
            out.push_str("  targets: []\n");
        } else {
            out.push_str("  targets:\n");
        }
        for target in &config.security.targets {
            let _ = writeln!(out, "    - {}", scalar(target));
        }
        if let Some(stack) = &config.security.stack {
            out.push_str(
                "  # A compose file the attack starts on an internal network and\n  \
                 # attacks, once confirmed with `devflow config set security.stack`.\n",
            );
            let _ = writeln!(out, "  stack: {}", scalar(stack));
        }
    }
    if config.version != V1 && !config.locked.is_empty() {
        out.push_str("\n# Fields a project extending this file may not change.\nlocked:\n");
        for path in &config.locked {
            let _ = writeln!(out, "  - {}", scalar(path));
        }
    }
    out
}

fn checks(dialect: &Dialect, out: &mut String, indent: &str, checks: &[Check]) {
    if checks.is_empty() {
        let _ = writeln!(out, "{indent}checks: []");
        return;
    }
    let _ = writeln!(
        out,
        "{indent}# Run by {} from the project's root for the evidence on the {}.\n\
         {indent}# report: junit | vitest | jest | cargo | none\n\
         {indent}checks:",
        dialect.product, dialect.work_item
    );
    listed(out, indent, checks);
}

/// The release's checks, written only when there are some.
fn release(dialect: &Dialect, out: &mut String, indent: &str, checks: &[Check]) {
    if checks.is_empty() {
        return;
    }
    let _ = writeln!(
        out,
        "{indent}# Run once for a release, never for each {}'s evidence nor by\n\
         {indent}# the gate: {} runs one when `checks` names it.\n\
         {indent}release:",
        dialect.work_item, dialect.tools.evidence
    );
    listed(out, indent, checks);
}

fn listed(out: &mut String, indent: &str, checks: &[Check]) {
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
    if dir != crate::config::default_e2e_dir() {
        let _ = writeln!(out, "    e2e_dir: {}", scalar(dir));
    }
}

fn stages_v1(dialect: &Dialect, out: &mut String, config: &Config) {
    let stages = &config.stages;
    out.push_str("\nstages:\n");
    out.push_str("  # approve: person stops for the person's yes; none goes on.\n");
    approved(out, "briefing", &stages.briefing);
    plain(out, "context", &stages.context);
    approved(out, "plan", &stages.plan);
    let execution = &stages.execution;
    let _ = writeln!(out, "  execution:\n    enabled: {}", execution.enabled);
    checks(dialect, out, "    ", &execution.checks);
    release(dialect, out, "    ", &execution.release);
    e2e_dir(out, &execution.e2e_dir);
    model(out, execution.model.as_deref());
    plain(out, "review", &stages.review);
    if stages.attack != Attack::default() {
        out.push_str(ATTACK_SAID);
        out.push_str("  attack:\n");
        attack_fields(out, &stages.attack);
        model(out, stages.attack.model.as_deref());
    }
    let _ = writeln!(
        out,
        "  completion:\n    enabled: {}\n    gate: {}",
        stages.completion.enabled,
        scalar(&stages.completion.gate)
    );
    model(out, stages.completion.model.as_deref());
}

/// A built-in stage's own `model`, when it says one.
fn model(out: &mut String, model: Option<&str>) {
    if let Some(model) = model {
        let _ = writeln!(out, "    model: {}", scalar(model));
    }
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

fn stages_v2(dialect: &Dialect, out: &mut String, config: &Config) {
    let _ = write!(
        out,
        "\n# The stages, in order. uses: builtin/<stage> is {}'s own; an own\n\
         # stage uses project/<skill> ({}/skills/), personal/<skill>,\n\
         # skills/<name> (a skill already installed for the agent CLIs) or\n\
         # <team>/<skill>, with a gate: {{ command: … }} or {{ rubric: … }}.\n\
         # approve: person stops for the person's yes; none goes on.\n\
         stages:\n",
        dialect.product, dialect.folder
    );
    if config.flow.is_empty() {
        out.push_str("  []\n");
    }
    for step in &config.flow {
        // At its default it goes unsaid: a file that never named it stays as
        // it was, and reads the same.
        if step.builtin() == Some(crate::config::ATTACK)
            && config.stages.attack == Attack::default()
        {
            continue;
        }
        let _ = writeln!(out, "  - uses: {}", scalar(&step.uses));
        if step.builtin() != Some(crate::config::ATTACK) {
            let _ = writeln!(out, "    enabled: {}", config.is_on(step));
        }
        stage_fields(dialect, out, config, step);
        if let Some(stage) = step.builtin() {
            model(out, config.stages.model(stage));
        }
    }
}

fn stage_fields(dialect: &Dialect, out: &mut String, config: &Config, step: &Step) {
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
            checks(dialect, out, "    ", &stages.execution.checks);
            release(dialect, out, "    ", &stages.execution.release);
            e2e_dir(out, &stages.execution.e2e_dir);
        }
        (Some("completion"), _) => {
            let _ = writeln!(out, "    gate: {}", scalar(&stages.completion.gate));
        }
        (Some(crate::config::ATTACK), _) => {
            out.push_str(&ATTACK_SAID.replace("  #", "    #"));
            attack_fields(out, &stages.attack);
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

fn review(dialect: &Dialect, out: &mut String, config: &Config) {
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
             # sensitive path, and any re-review, is read by one devflow-all reviewer.\n",
        );
        if *scale == crate::scale::Scale::default() {
            out.push_str("  scale: true\n");
        } else {
            out.push_str("  scale:\n");
            let _ = writeln!(out, "    small_lines: {}", scale.small_lines);
            if scale.sensitive != crate::scale::Scale::default().sensitive {
                let globs: Vec<String> = scale.sensitive.iter().map(|one| scalar(one)).collect();
                let _ = writeln!(out, "    sensitive: [{}]", globs.join(", "));
            }
        }
    } else if config.review.scale_off {
        out.push_str(
            "  # Off: every review, a re-review too, gets the configured reviewers.\n  \
             scale: false\n",
        );
    }
    if config.review.verify != crate::config::Verify::Off {
        out.push_str(
            "  # The session runs each critical and high's PoC: advise asks it,\n  \
             # required also counts a high it did not confirm as medium.\n",
        );
        let _ = writeln!(out, "  verify: {}", config.review.verify.word());
    }
    if let Some(analysis) = &config.review.analysis {
        out.push_str(
            "  # One more reading, on a large model, of a diff past scale's small or\n  \
             # on a sensitive path.\n",
        );
        match &analysis.model {
            None => {
                let _ = writeln!(out, "  analysis: {}", analysis.enabled);
            }
            Some(model) => {
                let _ = writeln!(
                    out,
                    "  analysis:\n    enabled: {}\n    model: {}",
                    analysis.enabled,
                    scalar(model)
                );
            }
        }
    }

    let _ = write!(
        out,
        "\n# Decisions (Jev) answers typed questions about the gates. shadow logs\n\
         # them; enforce blocks, and {}.\n\
         # It is sent findings, criteria with their evidence, the brief and the\n\
         # plan — never the diff — through {}\n\
         # (OpenRouter unless changed), with no retention and no training.\n\
         # rubrics: a stage's own rubric, from {}/rubrics/.\n\
         decisions:\n",
        dialect.yaml_enforce, dialect.yaml_provider, dialect.folder
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

/// What the attack stage's `run` says, above it.
const ATTACK_SAID: &str =
    "  # The attack: devflow-security tries to exploit the change, and only a\n  \
     # finding an exploit test confirmed holds the item. off, sensitive (a\n  \
     # diff past small or on a sensitive path), per-item, or release (asked\n  \
     # by name).\n";

/// The attack stage's own fields but its model, four spaces in.
fn attack_fields(out: &mut String, attack: &Attack) {
    let _ = writeln!(out, "    run: {}", attack.run.word());
    if let Some(test) = &attack.test {
        let _ = writeln!(out, "    test: {}", scalar(test));
    }
    if let Some(sandbox) = attack.sandbox {
        let _ = writeln!(
            out,
            "    sandbox: {}   # auto | bwrap | docker | off",
            sandbox.word()
        );
    }
    if let Some(image) = &attack.image {
        let _ = writeln!(out, "    image: {}", scalar(image));
    }
    if let Some(at_once) = attack.concurrency {
        let _ = writeln!(out, "    concurrency: {at_once}");
    }
    if !attack.attackers.is_empty() {
        out.push_str("    attackers:\n");
        for attacker in &attack.attackers {
            let _ = writeln!(out, "      - agent: {}", attacker.agent.word());
            if let Some(model) = &attacker.model {
                let _ = writeln!(out, "        model: {}", scalar(model));
            }
        }
    }
    if !attack.regression.is_empty() {
        let _ = writeln!(out, "    regression: [{}]", attack.regression.join(", "));
    }
    let budget = &attack.budget;
    if !budget.is_empty() {
        out.push_str("    budget:\n");
        if let Some(cents) = budget.run_cents {
            let _ = writeln!(out, "      run_usd: {}", Budget::usd(cents));
        }
        if let Some(cents) = budget.month_cents {
            let _ = writeln!(out, "      month_usd: {}", Budget::usd(cents));
        }
    }
}

fn plain(out: &mut String, name: &str, stage: &Stage) {
    let _ = writeln!(out, "  {name}:\n    enabled: {}", stage.enabled);
    model(out, stage.model.as_deref());
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
    model(out, stage.model.as_deref());
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
