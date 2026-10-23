use serde_json::{json, Value};

use super::*;
use crate::findings::tests::finding;

#[test]
fn the_rubrics_devpit_ships_name_themselves_and_threshold_every_question() {
    for (name, text) in BUILT_IN {
        let rubric: Value = serde_json::from_str(text).expect("a rubric is JSON");
        assert_eq!(rubric["name"], name);
        let questions = rubric["questions"].as_object().expect("questions");
        for (id, question) in questions {
            assert!(
                matches!(question["type"].as_str(), Some("noul" | "choice")),
                "{name}.{id}"
            );
            assert!(
                rubric["thresholds"].get(id).is_some(),
                "{name}.{id} has no threshold, so it could only ever be grey"
            );
        }
    }
    let finding: Value = serde_json::from_str(BUILT_IN[0].1).expect("json");
    let severities: Vec<&str> = crate::config::Severity::ALL
        .iter()
        .map(|one| one.word())
        .collect();
    assert_eq!(
        finding["questions"]["severity"]["options"],
        json!(severities)
    );
}

#[test]
fn each_stage_is_judged_by_devpits_rubric_unless_devflow_yaml_names_its_own() {
    let mut config = Config::default();
    assert_eq!(rubric_for(&config, "review").as_deref(), Some(FINDING));
    assert_eq!(rubric_for(&config, "briefing").as_deref(), Some(BRIEF));
    assert_eq!(rubric_for(&config, "plan").as_deref(), Some(PLAN));
    assert_eq!(rubric_for(&config, "completion").as_deref(), Some(DONE));
    assert_eq!(rubric_for(&config, "context"), None);
    config
        .decisions
        .rubrics
        .insert("review".into(), "acme-finding".into());
    assert_eq!(
        rubric_for(&config, "review").as_deref(),
        Some("acme-finding")
    );
}

#[test]
fn a_state_is_cut_to_fit_and_never_carries_the_diff() {
    let mut big = finding("src/a.rs", 3, "high", "x");
    big["description"] = json!("why ".repeat(5_000));
    let others: Vec<Value> = (0..40)
        .map(|at| finding("src/a.rs", at + 1, "low", &"other ".repeat(100)))
        .collect();
    let others: Vec<&Value> = others.iter().collect();
    let state = finding_state(&big, &others, &[(1, 9)], &["a criterion".to_owned()]);
    assert!(
        state.to_string().len() <= MOST_STATE,
        "{}",
        state.to_string().len()
    );
    assert_eq!(state["changed"], json!(["1-9"]));
    assert_eq!(state["finding"]["file"], "src/a.rs");
    assert!(state["others_here"]
        .as_array()
        .is_some_and(|all| all.len() <= 20));
    assert!(
        state["finding"].get("agent").is_none(),
        "who found it is not Jev's to weigh"
    );
}

#[test]
fn the_lines_a_diff_changed_are_read_per_file() {
    let diff = "diff --git a/src/a.rs b/src/a.rs\n--- a/src/a.rs\n+++ b/src/a.rs\n@@ -10,3 +10,4 @@ fn main() {\n a\n+b\n@@ -40 +41 @@\n-x\n+y\ndiff --git a/gone.rs b/gone.rs\n--- a/gone.rs\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-a\n-b\n";
    let changed = changed_lines(diff);
    assert_eq!(changed["src/a.rs"], [(10, 13), (41, 41)]);
    assert!(!changed.contains_key("gone.rs"));
}

fn said(mode: Mode, verdicts: Value, answers: Value) -> Said {
    Said {
        rubric: FINDING.into(),
        decision: Some("dcn_1".into()),
        mode,
        outcome: "fail".into(),
        verdicts,
        answers,
        skipped: None,
    }
}

fn not_real_and_milder() -> (Value, Value) {
    (
        json!({
            "real": { "verdict": "fail", "value": 0.1 },
            "severity": { "verdict": "pass", "value": 0.8 },
            "duplicate": { "verdict": "pass", "value": 0.05 },
        }),
        json!({ "severity": { "type": "choice", "choice": "low" } }),
    )
}

/// The same answer twice: in shadow it is written down and the finding is
/// what the reviewer said; in enforce it is set aside at Jev's severity.
#[test]
fn shadow_records_jevs_word_and_enforce_acts_on_it() {
    let (verdicts, answers) = not_real_and_milder();
    let reviewed = finding("src/a.rs", 3, "high", "x");

    let mut shadowed = reviewed.clone();
    on_finding(
        &mut shadowed,
        &said(Mode::Shadow, verdicts.clone(), answers.clone()),
    );
    assert_eq!(shadowed["severity"], "high");
    assert_eq!(shadowed["jev"]["real"], 0.1);
    assert_eq!(shadowed["jev"]["decision"], "dcn_1");
    assert!(shadowed["jev"].get("set_aside").is_none());
    let block_on = [crate::config::Severity::High];
    assert_eq!(
        crate::findings::blocking(&[shadowed], &block_on, crate::config::Verify::Off).len(),
        1
    );

    let mut enforced = reviewed.clone();
    on_finding(&mut enforced, &said(Mode::Enforce, verdicts, answers));
    assert_eq!(enforced["jev"]["set_aside"], true);
    assert_eq!(enforced["severity"], "low");
    assert!(
        crate::findings::blocking(&[enforced], &block_on, crate::config::Verify::Off).is_empty()
    );
}

#[test]
fn jev_never_raises_a_finding_to_high_without_a_poc_nor_acts_on_no_answer() {
    let verdicts = json!({ "severity": { "verdict": "pass", "value": 0.9 } });
    let answers = json!({ "severity": { "choice": "critical" } });
    let mut medium = finding("a.rs", 1, "medium", "x");
    on_finding(
        &mut medium,
        &said(Mode::Enforce, verdicts.clone(), answers.clone()),
    );
    assert_eq!(medium["severity"], "medium");
    let mut skipped = said(Mode::Enforce, verdicts, answers);
    skipped.skipped = Some("today's Decisions budget is spent".into());
    assert!(!skipped.acts());
    let mut low = finding("a.rs", 1, "low", "x");
    on_finding(&mut low, &skipped);
    assert_eq!(low["jev"]["skipped"], "today's Decisions budget is spent");
}

#[test]
fn a_duplicate_and_a_failing_plan_hold_only_in_enforce() {
    let verdicts = json!({ "duplicate": { "verdict": "fail", "value": 0.9 }, "testable": { "verdict": "fail", "value": 0.2 } });
    let shadowed = said(Mode::Shadow, verdicts.clone(), json!({}));
    assert!(!duplicate(&shadowed));
    assert_eq!(holds(&shadowed), None);
    let enforced = said(Mode::Enforce, verdicts, json!({}));
    assert!(duplicate(&enforced));
    let held = holds(&enforced).expect("held");
    assert!(
        held.contains("testable") && held.contains("duplicate"),
        "{held}"
    );
    assert_eq!(Said::of(&enforced.to_json()), Some(enforced));
}

#[test]
fn decisions_is_off_without_use_then_without_a_key_then_failing_on_the_last_call() {
    let state = |used, opted_out, key, failed| decisions_state(used, opted_out, key, failed).state;
    assert_eq!(state(false, false, true, None), DecisionsState::Off);
    assert_eq!(
        state(false, true, false, Some("refused")),
        DecisionsState::Off,
        "not used is off whatever else holds"
    );
    assert_eq!(state(true, true, true, None), DecisionsState::Off);
    assert_eq!(
        state(true, false, false, Some("refused")),
        DecisionsState::NoKey
    );
    assert_eq!(
        state(true, false, true, Some("refused")),
        DecisionsState::Failing
    );
    assert_eq!(state(true, false, true, None), DecisionsState::On);

    let off = decisions_state(false, false, true, None);
    assert!(off
        .reason
        .as_deref()
        .is_some_and(|why| why.contains("decisions.use")));
    let no_key = decisions_state(true, false, false, None);
    assert_eq!(
        no_key.reason.as_deref(),
        Some("no key — set one in Settings → Decisions")
    );
    let failing = decisions_state(true, false, true, Some("Decisions refused it (400): no"));
    assert_eq!(
        failing.reason.as_deref(),
        Some("Decisions refused it (400): no")
    );
    assert_eq!(decisions_state(true, false, true, None).reason, None);
    assert_eq!(
        json!(failing)["state"],
        "failing",
        "a reply names it as the panel reads it"
    );
    assert_eq!(json!(no_key)["state"], "no_key");
}

/// Where a finding sits is a fact Jev is told, not a question it answers:
/// out of the diff is said and, acting, sets nothing aside on its own; and a
/// severity one step from the reviewer's is within what Jev is sure of.
#[test]
fn the_anchor_is_told_to_jev_and_says_whether_a_finding_is_in_the_diff() {
    let mut outside = finding("src/b.rs", 7, "medium", "a caller the change broke");
    outside["anchor"] = json!("not_in_diff");
    let state = finding_state(&outside, &[], &[], &[]);
    assert_eq!(state["finding"]["anchor"], "not_in_diff");
    let rubric: Value = serde_json::from_str(BUILT_IN[0].1).expect("json");
    assert!(rubric["questions"].get("inDiff").is_none());
    assert_eq!(rubric["version"], "3");

    let real_but_milder = (
        json!({
            "real": { "verdict": "pass", "value": 0.9 },
            "severity": { "verdict": "pass", "value": 0.81 },
            "duplicate": { "verdict": "pass", "value": 0.05 },
        }),
        json!({ "severity": { "type": "choice", "choice": "low" } }),
    );
    let enforced = said(Mode::Enforce, real_but_milder.0, real_but_milder.1);
    on_finding(&mut outside, &enforced);
    assert_eq!(outside["jev"]["in_diff"], false);
    assert!(outside["jev"].get("set_aside").is_none(), "{outside}");
    assert_eq!(outside["severity"], "medium", "one step is within the band");

    let mut added = finding("src/a.rs", 3, "low", "x");
    added["anchor"] = json!("context");
    assert_eq!(in_diff(&added), Some(true));
    assert_eq!(in_diff(&finding("src/a.rs", 3, "low", "x")), None);
}
