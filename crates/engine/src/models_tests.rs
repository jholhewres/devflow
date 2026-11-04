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
