use serde_json::json;

use super::*;
use crate::config;

const COMPLETION: &str = include_str!("../../../flow/skills/devflow-completion/SKILL.md");

/// One `unit` check, and an `e2e` check that keeps screenshots; the review
/// stage as `review` says.
fn config_with(review: bool) -> Config {
    config::parse(&format!(
        "version: 1\nstages:\n  review:\n    enabled: {review}\n  execution:\n    checks:\n      - {{ name: unit, run: make test, report: junit }}\n      - {{ name: e2e, run: make e2e, report: junit, evidence: [screenshots] }}\n"
    ))
    .expect("a config")
}

fn criteria() -> Vec<String> {
    vec![
        "rename changes the title".to_owned(),
        "an empty title is refused".to_owned(),
    ]
}

/// evidence.json as `evidence` writes it: both checks passed,
/// both criteria green, the e2e check with one screenshot.
fn green_run() -> Value {
    json!({
        "card": "card_1",
        "green": true,
        "checks": [
            { "name": "unit", "result": "passed", "screenshots": [] },
            { "name": "e2e", "result": "passed", "screenshots": ["screenshots/e2e-rename.png"] },
        ],
        "criteria": [
            { "criterion": "rename changes the title", "on_card": true, "green": true,
              "tests": [{ "test": "rename_changes_the_title", "result": "passed" }] },
            { "criterion": "an  empty title is refused", "on_card": true, "green": true,
              "tests": [{ "test": "empty_title_is_refused", "result": "passed" }] },
        ],
        "spec": { "path": ".devflow/e2e/card_1-rename.spec.ts", "exists": true },
    })
}

const RUN: &str = "20261011T120000Z";

fn look(config: &Config, run: Option<&Value>, changed: Option<&str>) -> Checked {
    let criteria = criteria();
    checked(&Looked {
        config,
        card: "card_1",
        criteria: &criteria,
        run: run.map(|evidence| Run {
            name: RUN,
            evidence,
        }),
        review: None,
        changed,
        stages: &[],
        unreviewed: None,
        no_code: false,
    })
}

#[test]
fn a_card_whose_checks_never_ran_is_not_done() {
    let config = config_with(false);
    let found = look(&config, None, None);
    assert!(!found.missing.is_empty());
    assert!(found.missing[0].contains("`evidence`"), "{found:?}");
    let gate = Gate::new(found, None, RUN);
    assert!(!gate.passed());
    assert_eq!(gate.counted(), (0, 2));
}

#[test]
fn a_green_run_after_the_last_change_with_every_criterion_proved_passes() {
    let config = config_with(false);
    let run = green_run();
    let found = look(&config, Some(&run), Some("20261011T115959Z"));
    assert_eq!(found.missing, Vec::<String>::new());
    let gate = Gate::new(found, None, "20261011T120500Z");
    assert!(gate.passed());
    assert_eq!(gate.counted(), (2, 2));
    assert_eq!(answer(&gate, Some("gate.json"))["result"], "passed");
}

/// Without a way to tell when the code changed, a green run is enough.
#[test]
fn an_unknown_last_change_leaves_a_green_run_enough() {
    let config = config_with(false);
    let run = green_run();
    assert!(look(&config, Some(&run), None).missing.is_empty());
}

#[test]
fn code_changed_after_the_run_sends_the_card_back_to_its_checks() {
    let config = config_with(false);
    let run = green_run();
    let found = look(&config, Some(&run), Some("20261011T120001Z"));
    assert_eq!(found.missing.len(), 1, "{found:?}");
    assert!(found.missing[0].contains("changed after run"), "{found:?}");
}

#[test]
fn a_failed_skipped_or_inconclusive_check_is_named_with_what_fixes_it() {
    let config = config_with(false);
    let mut run = green_run();
    run["checks"][0]["result"] = json!("failed");
    run["checks"][1]["result"] = json!("inconclusive");
    let found = look(&config, Some(&run), None);
    assert!(found
        .missing
        .iter()
        .any(|item| item.contains("`unit` failed")));
    assert!(found
        .missing
        .iter()
        .any(|item| item.contains("`e2e` left no junit report")
            && item.contains("set its report to none")));

    run["checks"] = json!([{ "name": "unit", "result": "passed" }]);
    let found = look(&config, Some(&run), None);
    assert!(found
        .missing
        .iter()
        .any(|item| item.contains("`e2e` did not run")));
}

#[test]
fn a_criterion_with_no_test_or_a_red_one_is_named() {
    let config = config_with(false);
    let mut run = green_run();
    run["criteria"][1]["green"] = json!(false);
    run["criteria"][1]["tests"][0]["result"] = json!("failed");
    run["criteria"].as_array_mut().expect("criteria").remove(0);
    let found = look(&config, Some(&run), None);
    let gate = Gate::new(found, None, RUN);
    assert_eq!(gate.counted(), (0, 2));
    let missing = &gate.checked.missing;
    assert!(missing
        .iter()
        .any(|item| item.contains("\"rename changes the title\": names no test")));
    assert!(missing
        .iter()
        .any(|item| item.contains("`empty_title_is_refused` failed")));
}

#[test]
fn the_cards_own_spec_with_no_screenshot_is_missing_its_visual_proof() {
    let config = config_with(false);
    let mut run = green_run();
    run["checks"][1]["screenshots"] = json!([]);
    let found = look(&config, Some(&run), None);
    assert!(found
        .missing
        .iter()
        .any(|item| item.contains("kept no screenshot")));
    run["spec"]["exists"] = json!(false);
    assert!(look(&config, Some(&run), None).missing.is_empty());
}

fn reviewed_with(config: &Config, findings: &Value, at: &str, changed: Option<&str>) -> Checked {
    let run = green_run();
    let criteria = criteria();
    checked(&Looked {
        config,
        card: "card_1",
        criteria: &criteria,
        run: Some(Run {
            name: RUN,
            evidence: &run,
        }),
        review: Some(Review { at, findings }),
        changed,
        stages: &[],
        unreviewed: None,
        no_code: false,
    })
}

#[test]
fn a_review_of_a_commit_the_code_moved_on_from_holds_the_card() {
    let config = config_with(true);
    let run = green_run();
    let criteria = criteria();
    let findings = json!({ "verdict": "approve", "findings": [] });
    let looked = |unreviewed| {
        checked(&Looked {
            config: &config,
            card: "card_1",
            criteria: &criteria,
            run: Some(Run {
                name: RUN,
                evidence: &run,
            }),
            review: Some(Review {
                at: "20261011T121000Z",
                findings: &findings,
            }),
            changed: None,
            stages: &[],
            unreviewed,
            no_code: false,
        })
    };
    assert!(looked(None).missing.is_empty());
    let held = looked(Some("98097779aaaabbbbcccc"));
    assert_eq!(held.missing.len(), 1, "{held:?}");
    assert!(
        held.missing[0].contains("98097779aaaa") && held.missing[0].contains("review again"),
        "{held:?}"
    );
}

#[test]
fn a_finding_in_block_on_holds_the_card_and_one_below_it_does_not() {
    let config = config_with(true);
    let finding = |severity: &str| json!({ "file": "src/cli.rs", "line": 12, "severity": severity, "title": "title not trimmed" });
    let low = json!({ "verdict": "approve", "findings": [finding("low")] });
    let found = reviewed_with(&config, &low, "20261011T121000Z", None);
    assert!(found.missing.is_empty(), "{found:?}");
    assert_eq!(
        found.review.as_deref(),
        Some("verdict approve, 0 in block_on")
    );

    let high = json!({ "verdict": "request_changes", "findings": [finding("high")] });
    let found = reviewed_with(&config, &high, "20261011T121000Z", None);
    assert_eq!(found.missing.len(), 1);
    assert!(found.missing[0].contains("`src/cli.rs:12` title not trimmed (high)"));
}

#[test]
fn the_review_is_asked_for_only_where_its_stage_is_on_and_must_follow_the_last_change() {
    let run = green_run();
    let on = config_with(true);
    let found = look(&on, Some(&run), None);
    assert!(found
        .missing
        .iter()
        .any(|item| item.contains("no review yet")));
    assert!(look(&config_with(false), Some(&run), None)
        .missing
        .is_empty());

    let clear = json!({ "verdict": "approve", "findings": [] });
    let found = reviewed_with(&on, &clear, "20261011T115000Z", Some("20261011T115500Z"));
    assert!(found
        .missing
        .iter()
        .any(|item| item.contains("review is older than the last change")));
}

fn judged(mode: Mode, outcome: &str) -> Judged {
    Judged {
        rubric: "devflow-done".to_owned(),
        mode,
        outcome: outcome.to_owned(),
        said: vec!["inScope".to_owned()],
    }
}

#[test]
fn a_failing_rubric_holds_the_card_only_in_enforce_and_a_skip_never_does() {
    let config = config_with(false);
    let run = green_run();
    let gate = |decisions| Gate::new(look(&config, Some(&run), None), decisions, RUN);
    assert!(gate(None).passed(), "without Decisions the checks decide");
    assert!(
        gate(Some(judged(Mode::Shadow, "fail"))).passed(),
        "shadow only records"
    );
    assert!(gate(Some(judged(Mode::Enforce, "skipped"))).passed());
    assert!(gate(Some(judged(Mode::Enforce, "grey"))).passed());
    let held = gate(Some(judged(Mode::Enforce, "fail")));
    assert!(!held.passed());
    assert!(held.checked.missing[0].contains("Decisions judged devflow-done failing (inScope)"));
    assert_eq!(recorded(&held)["decisions"]["mode"], "enforce");
}

/// The completion skill tells the agent the line the gate comment starts
/// with; the gate writes that line.
#[test]
fn the_comment_starts_with_the_line_the_completion_skill_names() {
    assert!(COMPLETION.contains("[devflow] gate: <n> of <m> criteria with evidence"));
    assert!(COMPLETION.contains("`gate`"));
    let config = config_with(false);
    let run = green_run();
    let gate = Gate::new(look(&config, Some(&run), None), None, RUN);
    let said = comment(&gate);
    assert!(
        said.starts_with("[devflow] gate: 2 of 2 criteria with evidence\n"),
        "{said}"
    );
    assert!(said.contains("| Claim | Evidence | Fresh |"));
    assert!(said.contains("| rename changes the title | `rename_changes_the_title` passed in run"));
    assert!(said.ends_with("Passed.\n"));
}

fn stop(continued: bool, cap: usize) -> Hook {
    Hook {
        event: Event::Stop,
        session: Some("s-1".to_owned()),
        continued,
        agent: None,
        transcript: None,
        pane: None,
        cap,
    }
}

fn failing(seen: usize) -> Option<(String, String)> {
    Some((format!("look {seen}"), "no run".to_owned()))
}

#[test]
fn a_stop_is_sent_back_until_the_cap_and_then_only_warned_about() {
    let mut streak = Streak::default();
    assert_eq!(
        said(&stop(false, 3), &mut streak, failing(0)),
        Said::Block("no run".into())
    );
    for seen in 1..3 {
        assert!(matches!(
            said(&stop(true, 3), &mut streak, failing(seen)),
            Said::Block(_)
        ));
    }
    let past = said(&stop(true, 3), &mut streak, failing(3));
    let Said::Warn(message) = past else {
        panic!("past the cap the gate warns: {past:?}")
    };
    assert!(
        message.contains("after sending it back 3 times"),
        "{message}"
    );
    assert_eq!(streak, Streak::default());
}

#[test]
fn a_turn_sent_back_that_changed_nothing_is_let_end_with_a_warning() {
    let mut streak = Streak::default();
    let same = || Some(("the same look".to_owned(), "no run".to_owned()));
    assert!(matches!(
        said(&stop(false, 8), &mut streak, same()),
        Said::Block(_)
    ));
    assert!(matches!(
        said(&stop(true, 8), &mut streak, same()),
        Said::Warn(_)
    ));
}

#[test]
fn a_stop_the_cli_did_not_continue_starts_the_count_again_and_a_pass_ends_it() {
    let mut streak = Streak {
        blocks: 8,
        last: Some("old".to_owned()),
    };
    assert!(matches!(
        said(&stop(false, 8), &mut streak, failing(1)),
        Said::Block(_)
    ));
    assert_eq!(streak.blocks, 1);
    assert_eq!(said(&stop(true, 8), &mut streak, None), Said::Let);
    assert_eq!(streak, Streak::default());
}

#[test]
fn the_reply_is_what_claude_code_and_codex_read() {
    assert_eq!(reply(&Said::Let), json!({}));
    assert_eq!(
        reply(&Said::Block("why".into())),
        json!({ "decision": "block", "reason": "why" })
    );
    assert_eq!(
        reply(&Said::Warn("told".into())),
        json!({ "systemMessage": "told" })
    );
}

#[test]
fn asked_reads_what_the_hooks_send_and_drops_what_their_cli_left_unfilled() {
    let from_claude = asked(&json!({
        "event": "SubagentStop", "session": "s-1", "stop_hook_active": "true",
        "agent": "a-1", "transcript": "${agent_transcript_path}", "cap": "3",
    }))
    .expect("a hook");
    let hook = from_claude.hook.expect("the hook");
    assert_eq!(hook.event, Event::SubagentStop);
    assert!(hook.continued);
    assert_eq!(hook.transcript, None);
    assert_eq!(hook.cap, 3);

    let from_codex = asked(&json!({ "event": "Stop", "stop_hook_active": false }))
        .expect("a hook")
        .hook
        .expect("the hook");
    assert!(!from_codex.continued);
    assert_eq!(from_codex.cap, CAP);

    assert_eq!(
        asked(&json!({ "card": "c" }))
            .expect("a card")
            .card
            .as_deref(),
        Some("c")
    );
    assert!(asked(&json!({})).is_err());
    assert!(asked(&json!({ "card": "c", "why": 1 })).is_err());
    assert!(asked(&json!({ "event": "PreToolUse" })).is_err());
}

#[test]
fn the_cap_follows_the_clis_own_and_is_never_endless() {
    assert_eq!(cap_of(None), CAP);
    assert_eq!(cap_of(Some("2")), 2);
    assert_eq!(cap_of(Some("0")), CAP);
    assert_eq!(cap_of(Some("many")), CAP);
    assert_eq!(cap_of(Some("100000")), MOST_CAP);
}

#[test]
fn only_the_plans_cards_are_held_and_not_the_brief() {
    assert!(gated_card("[devflow] Rename a card"));
    assert!(!gated_card("[devflow] Brief: Renaming"));
    assert!(!gated_card("Rename a card"));
}

#[test]
fn a_subagent_is_held_only_for_code_changed_after_it_began() {
    let began = Some("20261011T120000Z");
    assert!(subagent_changed(Some("20261011T120001Z"), began));
    assert!(!subagent_changed(Some("20261011T115959Z"), began));
    assert!(!subagent_changed(None, began));
    assert!(!subagent_changed(Some("20261011T120001Z"), None));
}

/// A run whose second criterion is proved by a screenshot alone, as the
/// evidence tool records it when the file is (or is not) there.
fn proved_run(there: bool) -> Value {
    let mut run = green_run();
    run["criteria"][1]["tests"] = json!([]);
    run["criteria"][1]["green"] = json!(there);
    run["criteria"][1]["proof"] =
        json!({ "kind": "screenshot", "path": "shots/refused.png", "exists": there });
    run
}

#[test]
fn a_criterion_proved_by_a_screenshot_that_is_there_passes_and_a_missing_one_does_not() {
    let config = config_with(false);
    let run = proved_run(true);
    let found = look(&config, Some(&run), None);
    assert_eq!(found.missing, Vec::<String>::new());
    assert!(
        found.rows[1]
            .evidence
            .contains("proved by screenshot shots/refused.png"),
        "{found:?}"
    );

    let run = proved_run(false);
    let found = look(&config, Some(&run), None);
    assert!(
        found.missing.iter().any(|item| item
            .contains("screenshot shots/refused.png is not in the run's folder or the checkout")),
        "{found:?}"
    );
}

fn look_no_code(config: &Config, run: &Value, no_code: bool) -> Checked {
    let criteria = criteria();
    checked(&Looked {
        config,
        card: "card_1",
        criteria: &criteria,
        run: Some(Run {
            name: RUN,
            evidence: run,
        }),
        review: None,
        changed: None,
        stages: &[],
        unreviewed: None,
        no_code,
    })
}

#[test]
fn an_evidence_card_with_no_code_closes_on_its_proofs_without_a_review() {
    let review_on = config_with(true);
    let run = proved_run(true);
    assert_eq!(
        look_no_code(&review_on, &run, true).missing,
        Vec::<String>::new()
    );
    assert!(look_no_code(&review_on, &run, false)
        .missing
        .iter()
        .any(|item| item.contains("no review yet")));

    // Without a review, a criterion with neither a proof nor a test still holds it.
    let mut bare = run.clone();
    bare["criteria"].as_array_mut().expect("criteria").remove(1);
    assert!(look_no_code(&review_on, &bare, true)
        .missing
        .iter()
        .any(|item| item.contains("\"an empty title is refused\": names no test")));
}

#[test]
fn a_card_is_evidence_or_a_doc_by_its_kind_line_or_what_the_gate_was_told() {
    assert!(proof_only(
        "Screenshots of the board.\n\nKind: evidence\n",
        None
    ));
    assert!(proof_only("- **Kind:** Doc\n", None));
    assert!(!proof_only("Kind: code\n", None));
    assert!(!proof_only("Rename a card.\n", None));
    assert!(proof_only("Rename a card.\n", Some("evidence")));
    assert!(!proof_only("Kind: evidence\n", Some("code")));

    let files = |names: &[&str]| {
        names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>()
    };
    assert!(changed_no_code(&[]));
    assert!(changed_no_code(&files(&[
        "docs/shots/Before.PNG",
        "docs/a0.md"
    ])));
    assert!(!changed_no_code(&files(&["docs/a0.md", "src/main.rs"])));
    assert!(!changed_no_code(&files(&["Makefile"])));

    let told = asked(&json!({ "card": "c", "kind": "doc" })).expect("a kind");
    assert_eq!(told.kind.as_deref(), Some("doc"));
    assert!(asked(&json!({ "card": "c", "kind": "screenshots" })).is_err());
}
