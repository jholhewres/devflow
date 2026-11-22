use super::*;
use crate::config::parse;

#[test]
fn a_tier_is_the_engines_model_for_claude_and_codexs_own_default() {
    use crate::review::model_for;
    assert_eq!(
        model_for(Agent::Claude, Some("small")).as_deref(),
        Some("sonnet")
    );
    assert_eq!(
        model_for(Agent::Claude, Some("large")).as_deref(),
        Some("opus")
    );
    assert_eq!(model_for(Agent::Claude, Some("default")), None);
    assert_eq!(model_for(Agent::Codex, Some("small")), None);
    assert_eq!(model_for(Agent::Codex, Some("large")), None);
    assert_eq!(
        model_for(Agent::Codex, Some("gpt-5-mini")).as_deref(),
        Some("gpt-5-mini")
    );
}

#[test]
fn with_nothing_said_the_session_runs_small_and_nothing_else_changes() {
    let config = parse("version: 2\n").expect("valid");
    assert_eq!(preset(&config), Models::Economy);
    assert_eq!(
        session_model(&config, Agent::Claude).as_deref(),
        Some("sonnet")
    );
    assert_eq!(session_model(&config, Agent::Codex), None);
    assert!(!analysis_on(&config));
    assert_eq!(review_default(&config), None);
}

#[test]
fn a_stages_own_model_beats_the_preset() {
    let config = parse(
        "version: 2\nmodels: quality\nstages:\n  - uses: builtin/execution\n    model: small\n  - uses: builtin/review\n",
    )
    .expect("valid");
    assert_eq!(
        session_model(&config, Agent::Claude).as_deref(),
        Some("sonnet")
    );
    assert_eq!(stage_model(&config, ANALYSIS).as_deref(), Some("large"));
    assert_eq!(review_default(&config).as_deref(), Some("large"));
    assert!(analysis_on(&config));
}

#[test]
fn a_preset_turns_the_analysis_on_unless_the_review_says_no() {
    let off = parse("version: 2\nmodels: economy\nreview:\n  analysis: false\n").expect("valid");
    assert!(!analysis_on(&off));
    let on =
        parse("version: 2\nreview:\n  analysis:\n    model: claude-opus-5-5\n").expect("valid");
    assert!(analysis_on(&on));
    assert_eq!(
        stage_model(&on, ANALYSIS).as_deref(),
        Some("claude-opus-5-5")
    );
    assert_eq!(review_default(&on).as_deref(), Some("small"));
}

#[test]
fn a_reviewers_own_model_always_wins() {
    let config = parse(
        "version: 2\nmodels: quality\nreview:\n  analysis: false\n  reviewers:\n    - agent: claude\n      persona: devflow-spec\n      model: haiku\n    - agent: codex\n      persona: devflow-security\n",
    )
    .expect("valid");
    let models: Vec<Option<String>> = readers(&config, false, &[], "")
        .into_iter()
        .map(|reader| reader.reviewer.model)
        .collect();
    assert_eq!(models, [Some("haiku".to_owned()), Some("large".to_owned())]);
}

#[test]
fn the_plan_says_each_stages_model_and_the_sessions() {
    let config = parse("version: 2\nmodels: economy\n").expect("valid");
    let plan = plan(&config, Agent::Claude);
    assert_eq!(plan["preset"], "economy");
    assert_eq!(plan["stages"]["execution"], "small");
    assert_eq!(plan["stages"]["analysis"], "large");
    assert_eq!(plan["session"], "sonnet");
    assert_eq!(plan["analysis"], true);
}

#[test]
fn each_stage_and_reviewer_says_its_model_and_where_it_came_from() {
    let config = crate::config::parse(
        "version: 2\nstages:\n  - uses: builtin/plan\n    model: large\n  - uses: builtin/execution\n  - uses: builtin/review\nreview:\n  reviewers:\n    - { agent: claude, persona: devflow-security, model: claude-opus-5-5 }\n    - { agent: codex, persona: devflow-spec }\n  attack: sensitive\n",
    )
    .expect("config");
    let rows = origins(&config, Agent::Claude);
    let row = |stage: &str, who: Option<&str>| {
        rows.iter()
            .find(|row| row.stage == stage && row.who.as_deref() == who)
            .unwrap_or_else(|| panic!("{stage} {who:?}: {rows:#?}"))
    };
    let plan = row("plan", None);
    assert_eq!(
        (plan.said.as_deref(), plan.from),
        (Some("large"), From::Stage)
    );
    assert_eq!(plan.runs_on.as_deref(), Some("opus"));
    let execution = row("execution", None);
    assert_eq!(
        (execution.said.as_deref(), execution.from),
        (Some("small"), From::Preset)
    );
    let briefing = row("briefing", None);
    assert_eq!(
        (briefing.said.as_deref(), briefing.from),
        (None, From::Default)
    );
    let security = row("review", Some("claude devflow-security"));
    assert_eq!(
        (security.said.as_deref(), security.from),
        (Some("claude-opus-5-5"), From::Reviewer)
    );
    // Before any preset is said, a reviewer naming none runs on its CLI's default.
    let spec = row("review", Some("codex devflow-spec"));
    assert_eq!((spec.said.as_deref(), spec.from), (None, From::Default));
    let attack = row("attack", None);
    assert_eq!(
        (attack.said.as_deref(), attack.from),
        (Some("large"), From::Preset)
    );
    assert!(
        rows.iter().all(|row| row.stage != "analysis"),
        "the analysis is off"
    );
    assert_eq!(plan_json_rows(&config).len(), rows.len());
}

fn plan_json_rows(config: &Config) -> Vec<serde_json::Value> {
    plan(config, Agent::Claude)["origins"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// The preset devflow falls back to is the one the measurements recommend
/// writing, read from the doc's own words.
#[test]
fn the_fallback_preset_is_the_one_the_measurements_recommend() {
    let measured = include_str!("../../../docs/measurements/2026-11-presets.md");
    let said = measured
        .split("write `models: ")
        .nth(1)
        .and_then(|rest| rest.split('`').next())
        .expect("the doc recommends a preset");
    assert_eq!(said, preset(&Config::default()).word());
}

#[test]
fn only_per_item_and_sensitive_read_a_diff_for_the_attack() {
    for (run, reads) in [
        ("off", false),
        ("release", false),
        ("sensitive", true),
        ("per-item", true),
    ] {
        let config = parse(&format!(
            "version: 1\nstages:\n  attack: {{ run: {run} }}\n"
        ))
        .expect("config");
        assert_eq!(attack_reads_the_diff(&config), reads, "{run}");
        if !reads {
            assert!(!attack_on(&config, &["src/auth.rs".to_owned()], "+x"));
        }
    }
    let unnamed = parse("version: 1\n").expect("config");
    assert!(!attack_reads_the_diff(&unnamed), "no attack stage is off");
}
