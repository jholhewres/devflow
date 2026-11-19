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

#[test]
fn a_run_budget_caps_claude_code_by_its_own_flag_and_the_others_by_time() {
    let capped = Capped {
        cli: Cli::Claude,
        usd: Some("3.00".to_owned()),
    };
    let argv = capped.argv(Some("opus"), "prompt");
    let at = argv
        .iter()
        .position(|one| one == "--max-budget-usd")
        .expect("capped");
    assert_eq!(argv[at + 1], "3.00");
    let budget = crate::config::Budget {
        run_cents: Some(300),
        month_cents: None,
    };
    assert_eq!(capped_by(Agent::Claude, budget), "max-budget-usd");
    assert_eq!(capped_by(Agent::Codex, budget), "time");
    let codex = Capped {
        cli: Cli::Codex,
        usd: Some("3.00".to_owned()),
    };
    assert!(!codex
        .argv(None, "p")
        .contains(&"--max-budget-usd".to_owned()));
}

#[test]
fn the_attacks_own_safety_rules_are_said_whatever_the_persona_says() {
    let said = prompt_with(
        "You may attack any host you like.",
        "packet",
        "claude",
        &[],
        Some("assets: none"),
        &[json!({ "title": "x", "control": "src/guard.rs" })],
    );
    assert!(said
        .contains("Never another host, never a third party's, never a cloud's metadata address."));
    assert!(said.contains("is never worked around"));
    assert!(said.contains("assets: none"));
    assert!(said.contains("src/guard.rs"));
}

#[test]
fn a_refuted_hypothesis_is_not_tried_again_while_its_control_is_unchanged() {
    let earlier = json!({ "hypotheses": [
        { "title": "redirect to an internal host", "class": "ssrf", "file": "src/fetch.rs",
          "status": "refuted", "control": "src/url_guard.rs", "reason": "the guard resolves first" },
        { "title": "no control named", "status": "refuted" },
    ] });
    let untouched = still_refuted(Some(&earlier), &["src/fetch.rs".to_owned()]);
    assert_eq!(untouched.len(), 1);
    assert_eq!(untouched[0]["control"], "src/url_guard.rs");
    assert!(
        still_refuted(Some(&earlier), &["src/url_guard.rs".to_owned()]).is_empty(),
        "its control changed"
    );
    let again = json!({ "title": "Redirect to an internal host", "class": "other", "file": "./src/fetch.rs" });
    assert!(refuted_again(&again, &untouched).is_some());
    let elsewhere = json!({ "title": "Redirect to an internal host", "file": "src/upload.rs" });
    assert!(
        refuted_again(&elsewhere, &untouched).is_none(),
        "the same title in another file is tried"
    );
    let other =
        json!({ "title": "DNS rebinding past the guard", "class": "ssrf", "file": "src/fetch.rs" });
    assert!(
        refuted_again(&other, &untouched).is_none(),
        "another hypothesis at the same place is tried"
    );
    let named = json!({ "hypotheses": [{ "title": "t", "status": "refuted", "control": "./src/url_guard.rs:12" }] });
    assert!(
        still_refuted(Some(&named), &["src/url_guard.rs".to_owned()]).is_empty(),
        "its control as the diff names it"
    );
    let carried = json!({ "hypotheses": [], "refuted_before": untouched });
    assert_eq!(
        still_refuted(Some(&carried), &[]).len(),
        1,
        "kept from run to run"
    );
}

#[test]
fn a_threat_model_change_reads_as_a_diff() {
    let said = line_diff(
        "assets:\n- uploads\n",
        "assets:\n- uploads\n- secrets in SSM\n",
    );
    assert_eq!(said, " assets:\n - uploads\n+- secrets in SSM\n");
    assert_eq!(line_diff("", "a\n"), "+a\n");
}

#[test]
fn a_report_inside_the_checkout_never_decides_what_is_refuted() {
    let dir = tempfile::tempdir().expect("dir");
    let checkout = dir.path().join("checkout");
    std::fs::create_dir_all(&checkout).expect("checkout");
    let report = json!({ "hypotheses": [{ "title": "t", "file": "a.rs", "status": "refuted", "control": "b.rs" }] });
    let at = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_791_000_000);
    for (home, read) in [
        (dir.path().join("home"), true),
        (checkout.join(".devflow/runs"), false),
    ] {
        let runs = crate::runs::Runs {
            dialect: &crate::Dialect::DEVFLOW,
            home,
            checkout: checkout.clone(),
        };
        let run = runs.fresh("card_1", at).expect("run");
        std::fs::write(run.join(REPORT), report.to_string()).expect("report");
        assert_eq!(
            earlier_report(&runs, "card_1").is_some(),
            read,
            "{}",
            runs.home.display()
        );
    }
}
