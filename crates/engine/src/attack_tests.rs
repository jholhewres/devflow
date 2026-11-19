use serde_json::json;

use super::*;

#[test]
fn a_confirmed_hypothesis_at_block_on_is_followed_up_on_a_range_in_production() {
    let block_on = [Severity::Critical, Severity::High];
    let report = |severity: &str| json!({ "hypotheses": [{ "id": "h1", "status": "confirmed", "severity": severity, "exploit": { "test": "t" } }] });
    assert_eq!(
        verdict(&report("high"), &block_on, false),
        "request_changes"
    );
    assert_eq!(verdict(&report("high"), &block_on, true), "follow_up");
    assert_eq!(verdict(&report("medium"), &block_on, false), "approve");
    let mut tried = report("critical");
    tried["hypotheses"][0]["status"] = json!("tried");
    assert_eq!(
        verdict(&tried, &block_on, false),
        "approve",
        "only a run confirms"
    );
}

#[test]
fn an_exploit_belongs_inside_the_repository() {
    assert!(exploit_path("tests/a.test.ts").is_ok());
    for outside in [
        "../a.test.ts",
        "/etc/passwd",
        "tests/../../a",
        "",
        ".git/hooks/pre-commit",
        "sub/.git/config",
    ] {
        assert!(exploit_path(outside).is_err(), "{outside}");
    }
}

#[test]
fn two_hypotheses_never_share_a_folder_of_exploits() {
    let said = json!({ "hypotheses": [
        { "id": "h/1", "title": "a", "severity": "low", "status": "refuted", "reason": "r" },
        { "id": "h1", "title": "b", "severity": "low", "status": "refuted", "reason": "r" },
    ] });
    let read = read_answer(&said.to_string()).expect("read");
    assert_eq!(read["hypotheses"][0]["id"], "h1");
    assert_eq!(
        read["hypotheses"][1]["id"], "h2",
        "said twice, numbered anew"
    );
    let taken = json!({ "hypotheses": [
        { "id": "h2", "title": "a", "severity": "low", "status": "refuted", "reason": "r" },
        { "id": "h2", "title": "b", "severity": "low", "status": "refuted", "reason": "r" },
    ] });
    let read = read_answer(&taken.to_string()).expect("read");
    assert_eq!(
        read["hypotheses"][1]["id"], "h2-2",
        "never the same id again"
    );
}

#[test]
fn a_red_run_confirms_only_when_it_reached_its_test() {
    let test = "a forged cookie is refused";
    assert!(reached(
        "FAIL tests/a.test.ts\n  x a forged cookie is refused",
        test
    ));
    assert!(!reached("all good", test));
    assert!(!reached(
        "SyntaxError: Unexpected token in a forged cookie is refused",
        test
    ));
    assert!(!reached(
        "Cannot find module './session' from a forged cookie is refused",
        test
    ));
}

#[test]
fn an_attacker_that_gave_nothing_is_no_attack() {
    let failed_one = json!({ "attackers": [{ "agent": "claude", "reason": "not installed" }], "hypotheses": [] });
    assert_eq!(failed(&failed_one).as_deref(), Some("not installed"));
    let answered = json!({ "attackers": [{ "agent": "claude" }], "hypotheses": [] });
    assert!(
        failed(&answered).is_none(),
        "an attack that found nothing ran"
    );
}

#[test]
fn a_proof_says_which_side_failed() {
    let proof = |base: &str, head: &str| {
        json!({ "status": "confirmed", "verified": { "by": "sandbox" }, "proof": {
            "base": { "commit": "aaaaaaaaaaaaaaaa", "result": base },
            "head": { "commit": "bbbbbbbbbbbbbbbb", "result": head },
            "ran_at": "20261119T120000Z" } })
    };
    let none = json!({ "status": "confirmed", "verified": { "by": "sandbox" } });
    assert!(unproven(&none).expect("unproven").contains("no proof"));
    let at_base = unproven(&proof("green", "green")).expect("base");
    assert!(at_base.contains("at its base aaaaaaaaaaaa"), "{at_base}");
    let at_head = unproven(&proof("red", "red")).expect("head");
    assert!(
        at_head.contains("at HEAD bbbbbbbbbbbb") && at_head.contains("still open"),
        "{at_head}"
    );
    assert!(unproven(&proof("red", "green")).is_none());
    let report = json!({ "hypotheses": [
        { "status": "confirmed", "verified": { "by": "sandbox" }, "exploit": { "test": "a" } },
        { "status": "confirmed", "verified": { "by": "session" }, "exploit": { "test": "b" } },
    ] });
    let wanted: Vec<Value> = exploits(&report)
        .iter()
        .map(|one| one["test"].clone())
        .collect();
    assert_eq!(wanted, [json!("b")], "the sandbox's is held by its proof");
}

#[test]
fn only_its_proof_changes_what_the_sandbox_confirmed() {
    let mut report = json!({ "hypotheses": [{ "id": "h1", "status": "confirmed",
        "verified": { "by": "sandbox", "result": "confirmed", "evidence": "red" }, "exploit": { "test": "t" } }] });
    let refused = verified_on(
        &mut report,
        &[json!({ "hypothesis": "h1", "result": "refuted", "evidence": "green here" })],
    )
    .expect_err("the sandbox ran it");
    assert!(refused.contains("prove"), "{refused}");
    assert_eq!(report["hypotheses"][0]["status"], "confirmed");
}
