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

/// A confirmed hole carried past the cap is not shown fixed: at block_on it
/// holds as a run would. One carried with no exploit, or not run, does not.
#[test]
fn a_confirmed_hole_carried_past_the_cap_holds_at_block_on() {
    let block_on = [Severity::Critical, Severity::High];
    let report = |why: &str, status: &str| {
        json!({ "hypotheses": [], "carried": [{ "status": status, "severity": "high", "carried": why,
            "again": { "item": "card_1", "run": "20261119T120000Z", "id": "h13", "was": status } }] })
    };
    assert_eq!(
        verdict(&report("cap", "confirmed"), &block_on, false),
        "request_changes"
    );
    assert_eq!(
        verdict(&report("cap", "confirmed"), &block_on, true),
        "follow_up"
    );
    assert_eq!(
        verdict(&report("cap", "tried"), &block_on, false),
        "approve"
    );
    assert_eq!(
        verdict(&report("no_exploit", "confirmed"), &block_on, false),
        "approve"
    );
    assert_eq!(counts(&report("cap", "confirmed"))["carried"], 1);
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

/// What jest prints when an exploit fails on its own assertion.
const JEST_RED: &str = "\
FAIL tests/security/session.exploit.test.ts
  forged sessions
    \u{2715} accepts a cookie signed with any key (12 ms)

  \u{25cf} forged sessions \u{203a} accepts a cookie signed with any key

    expect(received).toBe(expected) // Object.is equality

    Expected: false
    Received: true

      at Object.<anonymous> (tests/security/session.exploit.test.ts:9:26)

Test Suites: 1 failed, 1 total
Tests:       1 failed, 1 total
";

/// What vitest prints for the same.
const VITEST_RED: &str = "\
 FAIL  tests/security/session.exploit.test.ts > forged sessions > accepts a cookie signed with any key
AssertionError: expected true to be false
 \u{276f} tests/security/session.exploit.test.ts:9:26

 Test Files  1 failed (1)
      Tests  1 failed (1)
";

#[test]
fn a_red_run_names_its_test_however_the_runner_joins_describe_and_test() {
    for named in [
        "forged sessions accepts a cookie signed with any key",
        "forged sessions \u{203a} accepts a cookie signed with any key",
        "forged sessions > accepts a cookie signed with any key",
        "accepts a cookie signed with any key",
    ] {
        assert!(reached(JEST_RED, named), "jest: {named}");
        assert!(reached(VITEST_RED, named), "vitest: {named}");
    }
    assert!(reached(
        "test exploits::forged_cookie_is_accepted ... FAILED",
        "exploits forged_cookie_is_accepted"
    ));
    assert!(!reached(
        JEST_RED,
        "forged sessions refuses an expired cookie"
    ));
    // A harness error is never the hole, whatever names the test.
    let broken = JEST_RED.replace("expect(received)", "Cannot find module './session'");
    assert!(!reached(
        &broken,
        "forged sessions accepts a cookie signed with any key"
    ));
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
    let mut settled_report = report.clone();
    settled(&mut settled_report, &[]);
    let listed: Vec<(Value, Value)> = settled_report["exploits"]
        .as_array()
        .expect("exploits")
        .iter()
        .map(|one| (one["test"].clone(), one["held_by"].clone()))
        .collect();
    assert_eq!(
        listed,
        [
            (json!("a"), json!("proof")),
            (json!("b"), json!("evidence"))
        ],
        "attack.json lists both, each with what holds it"
    );
}

#[test]
fn verified_names_the_test_the_session_ran() {
    let mut report = json!({ "hypotheses": [
        { "id": "h1", "status": "tried", "exploit": { "path": "tests/a.test.ts", "test": "a" } },
        { "id": "h2", "status": "tried", "exploit": { "path": "tests/b.test.ts", "test": "b" } },
    ] });
    verified_on(
        &mut report,
        &[
            json!({ "hypothesis": "h1", "result": "confirmed", "evidence": "red", "test": "a renamed" }),
            json!({ "hypothesis": "h2", "result": "refuted", "evidence": "green" }),
        ],
    )
    .expect("verified");
    let one = &report["hypotheses"][0]["verified"];
    assert_eq!(
        (&one["test"], &one["path"]),
        (&json!("a renamed"), &json!("tests/a.test.ts"))
    );
    assert_eq!(report["hypotheses"][1]["verified"]["test"], "b");
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
        "## Regression cases: (data)\n### ssrf: loopback\n{\"id\":\"loopback\"}\n",
    );
    assert!(said
        .contains("Never another host, never a third party's, never a cloud's metadata address."));
    assert!(said.contains("is never worked around"));
    assert!(said.contains("assets: none"));
    assert!(said.contains("src/guard.rs"));
    assert!(said.contains("## Regression cases") && said.contains("### ssrf: loopback"));
    assert!(!prompt("p", "packet", "claude", &[]).contains("## Regression cases"));
}

#[test]
fn an_answer_proposes_only_neutral_cases_of_a_known_class() {
    let said = json!({ "hypotheses": [], "cases": [
        { "class": "traversal", "input": "..;/..;/etc/hostname", "want": "rejected", "why": "a ;-split path" },
        { "class": "ssrf", "input": "http://metadata.someone.com/", "want": "rejected" },
    ] });
    let read = read_answer(&said.to_string()).expect("read");
    let cases = read["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 1, "{cases:?}");
    assert_eq!(cases[0]["class"], "traversal");
    assert_eq!(read["dropped_cases"][0]["class"], "ssrf", "{read}");
}

#[test]
fn a_refuted_hypothesis_is_not_tried_again_while_its_control_is_unchanged() {
    let earlier = json!({ "run": "20261122T142204Z", "hypotheses": [
        { "id": "h9", "title": "redirect to an internal host", "class": "ssrf", "file": "src/fetch.rs",
          "line": 112, "status": "refuted", "control": "src/url_guard.rs", "reason": "the guard resolves first" },
        { "title": "no control named", "status": "refuted" },
    ] });
    let fetch = ["src/fetch.rs".to_owned()];
    let untouched = still_refuted(Some(&earlier), Since::Change(&fetch));
    assert_eq!(untouched.len(), 1);
    assert_eq!(untouched[0]["control"], "src/url_guard.rs");
    assert_eq!(untouched[0]["run"], "20261122T142204Z");
    assert_eq!(untouched[0]["id"], "h9");
    assert!(
        still_refuted(
            Some(&earlier),
            Since::Change(&["src/url_guard.rs".to_owned()])
        )
        .is_empty(),
        "its control changed"
    );
    let again = json!({ "title": "Redirect to an internal host", "class": "other", "file": "./src/fetch.rs" });
    assert_eq!(refuted_again(&again, &untouched), Some(0));
    let elsewhere = json!({ "title": "Redirect to an internal host", "file": "src/upload.rs" });
    assert!(
        refuted_again(&elsewhere, &untouched).is_none(),
        "the same title in another file is tried"
    );
    let other = json!({ "title": "DNS rebinding past the guard", "class": "ssrf", "file": "src/fetch.rs",
        "line": 110, "status": "tried" });
    assert!(
        refuted_again(&other, &untouched).is_none(),
        "another hypothesis tried at the same place is tried"
    );
    let named = json!({ "hypotheses": [{ "title": "t", "status": "refuted", "control": "./src/url_guard.rs:12" }] });
    assert!(
        still_refuted(
            Some(&named),
            Since::Change(&["src/url_guard.rs".to_owned()])
        )
        .is_empty(),
        "its control as the diff names it"
    );
    let carried =
        json!({ "run": "20261123T000000Z", "hypotheses": [], "refuted_before": untouched });
    let kept = still_refuted(Some(&carried), Since::Change(&[]));
    assert_eq!(kept.len(), 1, "kept from run to run");
    assert_eq!(
        kept[0]["run"], "20261122T142204Z",
        "by the run that refuted it"
    );
}

/// Read against what changed since the earlier attack's head, a refutation
/// stands while no code in its path changed: neither its file nor its
/// control; one with no control named only while nothing changed. The
/// change's own files, which hold the file attacked, no longer decide.
#[test]
fn a_refutation_stands_while_no_new_code_is_in_its_path() {
    let earlier = json!({ "run": "20261122T142204Z", "hypotheses": [
        { "id": "h5", "title": "a gzip bomb", "class": "dos", "file": "src/fetch.rs", "line": 241,
          "status": "refuted", "control": "src/fetch.rs", "reason": "bytes counted" },
        { "id": "h6", "title": "secrets in the environment", "class": "secrets", "file": "deploy.yml",
          "line": 7, "status": "refuted", "control": "deploy.yml", "reason": "in a store" },
        { "id": "h7", "title": "no control named", "class": "redos", "file": "src/x.rs", "status": "refuted" },
        { "id": "h8", "title": "not run", "class": "ssrf", "file": "src/fetch.rs", "status": "not_run",
          "reason": "needs a target" },
    ] });
    let same = still_refuted(Some(&earlier), Since::Earlier(&[]));
    let ids: Vec<&str> = same.iter().filter_map(|one| one["id"].as_str()).collect();
    assert_eq!(ids, ["h5", "h6", "h7"], "nothing changed: {same:#?}");
    let fetch_changed = still_refuted(Some(&earlier), Since::Earlier(&["src/fetch.rs".to_owned()]));
    let ids: Vec<&str> = fetch_changed
        .iter()
        .filter_map(|one| one["id"].as_str())
        .collect();
    assert_eq!(ids, ["h6"], "new code in the others' path");
    let control_only = json!({ "run": "r", "hypotheses": [
        { "id": "h9", "title": "rebinding", "class": "ssrf", "file": "src/fetch.rs", "status": "refuted",
          "control": "src/guard.rs" } ] });
    assert!(still_refuted(
        Some(&control_only),
        Since::Earlier(&["src/guard.rs".to_owned()])
    )
    .is_empty());
    assert_eq!(
        still_refuted(
            Some(&control_only),
            Since::Change(&["src/fetch.rs".to_owned()])
        )
        .len(),
        1,
        "the change's files: only the control counts"
    );
    let not_run = not_run_before(Some(&earlier));
    assert_eq!(not_run.len(), 1);
    assert_eq!(not_run[0]["id"], "h8");
    assert_eq!(not_run[0]["run"], "20261122T142204Z");
}

/// An answered hypothesis is a refutation again when it says so
/// (`same_as`), when titled so in that file, or, refuted again itself, at
/// that place or behind that control in that file and class; one an
/// earlier attack did not run, when it says so, titled so or at its place.
#[test]
fn a_hypothesis_named_again_is_told_by_what_it_says_and_where_it_is() {
    let refuted = vec![
        json!({ "title": "A gzip bomb exhausts memory", "class": "dos", "file": "src/fetch.rs",
            "line": 241, "control": "src/fetch.rs", "run": "20261122T142204Z", "id": "h7" }),
        json!({ "title": "DNS rebinding between check and connect", "class": "ssrf",
            "file": "src/fetch.rs", "line": 170, "control": "src/guard.rs",
            "run": "20261122T142204Z", "id": "h9" }),
    ];
    let reworded = json!({ "title": "A compressed body inflates past the limit", "class": "denial-of-service",
        "file": "src/fetch.rs", "line": 243, "status": "refuted", "control": "src/fetch.rs" });
    assert_eq!(refuted_again(&reworded, &refuted), Some(0));
    let behind = json!({ "title": "A slow body holds the function", "class": "dos", "file": "src/fetch.rs",
        "line": 93, "status": "refuted", "control": "src/fetch.rs:104" });
    assert_eq!(
        refuted_again(&behind, &refuted),
        Some(0),
        "behind its control"
    );
    let moved = json!({ "title": "Rebinding past the address check", "class": "ssrf",
        "file": "src/guard.rs", "line": 173, "status": "refuted",
        "same_as": "20261122T142204Z:h9" });
    assert_eq!(refuted_again(&moved, &refuted), Some(1), "said so");
    let mut tried = reworded.clone();
    tried["status"] = json!("tried");
    assert!(
        refuted_again(&tried, &refuted).is_none(),
        "one tried may be another hole there"
    );
    let mut open = reworded;
    open["status"] = json!("not_run");
    assert!(refuted_again(&open, &refuted).is_none());
    let not_run = vec![
        json!({ "title": "Public services that trust the NAT egress", "class": "ssrf",
            "file": "src/fetch.rs", "line": 99, "run": "20261122T142204Z", "id": "h4" }),
    ];
    let again = json!({ "title": "Destinations that trust the network origin", "class": "ssrf",
        "file": "src/guard.rs", "line": 173, "status": "not_run", "same_as": "20261122T142204Z/h4" });
    assert_eq!(
        not_run_again(&again, &not_run).map(|one| &one["id"]),
        Some(&json!("h4"))
    );
    let near =
        json!({ "title": "Another", "class": "SSRF", "file": "./src/fetch.rs", "line": 101 });
    assert!(not_run_again(&near, &not_run).is_some(), "at its place");
    let unrelated =
        json!({ "title": "Another", "class": "ssrf", "file": "src/guard.rs", "line": 99 });
    assert!(not_run_again(&unrelated, &not_run).is_none());
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

#[test]
fn the_worst_scanner_findings_go_first_and_none_is_lost_without_a_word() {
    let mut findings: Vec<Value> = (0..MOST_SCANNER)
        .map(|at| json!({ "tool": "semgrep", "rule": format!("r{at}"), "severity": "low", "file": "a.rs", "line": 1 }))
        .collect();
    findings.push(json!({ "tool": "npm audit", "rule": "GHSA-x", "severity": "critical", "file": "package-lock.json", "line": 1 }));
    let evidence = json!({ "checks": [{ "findings": findings }] });
    let given = scanner_findings(Some(&evidence));
    assert_eq!(given.len(), MOST_SCANNER);
    assert_eq!(
        given[0]["rule"], "GHSA-x",
        "the critical one is given first"
    );
    assert_eq!(given[0]["id"], "s1");
    assert_eq!(scanner_left_out(Some(&evidence)), 1);
}

#[test]
fn hypotheses_at_one_place_and_class_are_one_naming_who_found_it() {
    let h = |file: &str, line: i64, class: &str, title: &str| json!({ "id": "h1", "file": file, "line": line, "class": class, "title": title, "status": "tried" });
    let kept = consolidated(vec![
        (
            "claude/large".to_owned(),
            vec![
                h("src/a.rs", 10, "ssrf", "fetch follows redirects"),
                h("src/b.rs", 1, "authz", "no owner check"),
            ],
        ),
        (
            "codex/default".to_owned(),
            vec![
                h("src/a.rs", 13, "ssrf", "redirect to metadata"),
                h("src/a.rs", 10, "traversal", "path in name"),
            ],
        ),
    ]);
    assert_eq!(kept.len(), 3, "{kept:#?}");
    assert_eq!(
        kept[0]["found_by"],
        json!(["claude/large", "codex/default"])
    );
    assert_eq!(
        kept[0]["title"], "fetch follows redirects",
        "the first found stands"
    );
    assert_eq!(kept[2]["found_by"], json!(["codex/default"]));
    let ids: Vec<&str> = kept.iter().filter_map(|one| one["id"].as_str()).collect();
    assert_eq!(ids, ["h1", "h2", "h3"]);
}

#[test]
fn attackers_naming_one_hole_tls_and_crypto_found_one_but_authz_beside_it_stays_apart() {
    let h = |line: i64, class: &str, title: &str| json!({ "id": "h1", "file": "./src/db.ts", "line": line, "class": class, "title": title, "status": "tried" });
    let kept = consolidated(vec![
        (
            "claude/large".to_owned(),
            vec![
                h(7, "tls", "rejectUnauthorized is false"),
                h(20, "ssl", "the CA is not pinned"),
            ],
        ),
        (
            "codex/default".to_owned(),
            vec![
                h(7, "Crypto", "the certificate is not checked"),
                h(7, "authz", "any tenant reads the pool"),
                h(23, "transport", "any CA is trusted"),
                // A few lines on, crypto is another hole: a weak hash.
                h(10, "crypto", "passwords hashed with md5"),
            ],
        ),
    ]);
    let said: Vec<(i64, Value)> = kept
        .iter()
        .map(|one| {
            (
                one["line"].as_i64().unwrap_or_default(),
                one["found_by"].clone(),
            )
        })
        .collect();
    assert_eq!(
        said,
        [
            (7, json!(["claude/large", "codex/default"])),
            (20, json!(["claude/large", "codex/default"])),
            (7, json!(["codex/default"])),
            (10, json!(["codex/default"])),
        ],
        "{kept:#?}"
    );
    assert_eq!(kept[2]["class"], "authz");
}

#[test]
fn an_attackers_own_hypotheses_stay_apart_and_the_one_that_went_furthest_stands() {
    let h = |line: i64, title: &str, status: &str, exploit: bool| {
        let mut one = json!({ "id": "h1", "file": "src/a.rs", "line": line, "class": "ssrf", "title": title, "status": status });
        if exploit {
            one["exploit"] = json!({ "path": "tests/x.rs", "test": "x", "code": "1" });
        }
        one
    };
    let alone = consolidated(vec![(
        "claude/default".to_owned(),
        vec![
            h(10, "redirect", "tried", false),
            h(12, "dns rebinding", "tried", false),
        ],
    )]);
    assert_eq!(alone.len(), 2, "one attacker's two hypotheses are two");
    let kept = consolidated(vec![
        (
            "claude/large".to_owned(),
            vec![h(10, "guarded", "refuted", false)],
        ),
        (
            "codex/default".to_owned(),
            vec![h(11, "redirect to metadata", "tried", true)],
        ),
    ]);
    assert_eq!(kept.len(), 1);
    assert_eq!(
        kept[0]["title"], "redirect to metadata",
        "the exploit stands over the refutation"
    );
    assert_eq!(
        kept[0]["found_by"],
        json!(["claude/large", "codex/default"])
    );
    assert!(kept[0]["exploit"].is_object());
}

#[test]
fn a_stacks_exploit_is_proven_at_head_and_the_sandbox_is_docker() {
    let proof = |base: &str, head: &str, stack: bool| {
        json!({ "status": "confirmed", "verified": { "by": "sandbox", "stack": stack }, "proof": {
            "base": { "commit": "aaaaaaaaaaaaaaaa", "result": base },
            "head": { "commit": "bbbbbbbbbbbbbbbb", "result": head },
            "ran_at": "20261120T000000Z", "stack": stack } })
    };
    assert!(
        unproven(&proof("skipped", "green", true)).is_none(),
        "the stack runs HEAD"
    );
    assert!(
        unproven(&proof("skipped", "red", true)).is_some(),
        "still open"
    );
    assert!(
        unproven(&proof("skipped", "green", false)).is_some(),
        "a plain one needs its base"
    );
    use crate::config::SandboxChoice;
    assert_eq!(sandbox_for(None, true), SandboxChoice::Docker);
    assert_eq!(
        sandbox_for(Some(SandboxChoice::Auto), true),
        SandboxChoice::Docker
    );
    assert_eq!(sandbox_for(None, false), SandboxChoice::Auto);
    assert_eq!(
        sandbox_for(Some(SandboxChoice::Bwrap), true),
        SandboxChoice::Bwrap
    );
}

/// An exploit joins the stack when the target it declares is one of the
/// stack's, however the attacker wrote its case or a trailing slash.
#[test]
fn a_declared_target_is_on_the_stack_however_it_is_written() {
    let targets = ["http://web:8080".to_owned()];
    let declaring = |target: &str| json!({ "exploit": { "target": target } });
    for said in ["http://web:8080", "HTTP://Web:8080/", " http://web:8080 "] {
        assert!(on_stack(Some(&targets), &declaring(said)), "{said}");
    }
    for said in ["", "http://web:9090", "http://web"] {
        assert!(!on_stack(Some(&targets), &declaring(said)), "{said}");
    }
    assert!(!on_stack(None, &declaring("http://web:8080")), "no stack");
}

/// A later attacker's own hypotheses stay apart too: two of its own at one
/// place are two, and one already merged with an earlier attacker's takes
/// no other of the same attacker.
#[test]
fn a_later_attackers_own_hypotheses_stay_apart() {
    let h = |line: i64, title: &str| json!({ "id": "h1", "file": "src/a.rs", "line": line, "class": "ssrf", "title": title, "status": "tried" });
    let apart = consolidated(vec![
        ("claude/large".to_owned(), vec![h(40, "elsewhere")]),
        (
            "codex/default".to_owned(),
            vec![h(10, "redirect"), h(12, "dns rebinding")],
        ),
    ]);
    assert_eq!(apart.len(), 3, "{apart:#?}");
    let merged_once = consolidated(vec![
        ("claude/large".to_owned(), vec![h(10, "redirect")]),
        (
            "codex/default".to_owned(),
            vec![h(11, "redirect to metadata"), h(12, "dns rebinding")],
        ),
    ]);
    assert_eq!(merged_once.len(), 2, "{merged_once:#?}");
    assert_eq!(
        merged_once[0]["found_by"],
        json!(["claude/large", "codex/default"])
    );
    assert_eq!(merged_once[1]["title"], "dns rebinding");
    assert_eq!(merged_once[1]["found_by"], json!(["codex/default"]));
}

#[test]
fn a_test_made_from_a_template_is_reached_by_any_of_its_cases() {
    let jest = "  \u{25cf} forged sessions \u{203a} accepts a cookie signed with admin\n\n    Expected: false\n";
    for named in [
        "forged sessions accepts a cookie signed with %s",
        "forged sessions \u{203a} accepts a cookie signed with $role",
        "accepts a cookie signed with $user.role",
        "accepts a %s signed with %s",
    ] {
        assert!(reached(jest, named), "{named}");
    }
    for not in [
        "forged sessions refuses a cookie signed with %s",
        // A placeholder stands for something, never for nothing.
        "accepts a cookie signed with admin%s",
        // Its text on two lines is no case of it.
        "forged sessions %s Expected: false",
    ] {
        assert!(!reached(jest, not), "{not}");
    }
    assert!(reached(
        "  \u{2715} costs 100% off (3 ms)",
        "costs 100%% off"
    ));
}

/// What each runner prints when an exploit fails on its own assertion, and
/// the name the attacker gave it.
const RED: [(&str, &str, &str); 5] = [
    (
        "go",
        "--- FAIL: TestSessionForgery (0.00s)\n    --- FAIL: TestSessionForgery/any_key_is_accepted (0.00s)\n        exploit_test.go:14: forged cookie accepted\nFAIL\nFAIL\texample.test/shop/session\t0.004s\n",
        "TestSessionForgery/any key is accepted",
    ),
    (
        "cargo",
        "running 1 test\ntest forged_cookie_is_accepted ... FAILED\n\nfailures:\n\n---- forged_cookie_is_accepted stdout ----\nthread 'forged_cookie_is_accepted' panicked at tests/exploit.rs:9:5\n\ntest result: FAILED. 0 passed; 1 failed\n",
        "forged_cookie_is_accepted",
    ),
    (
        "pytest",
        "____ TestSession.test_forged_cookie[admin] ____\nE   assert True is False\n=== short test summary info ===\nFAILED tests/test_exploit.py::TestSession::test_forged_cookie[admin] - assert True is False\n",
        "TestSession::test_forged_cookie",
    ),
    (
        "phpunit",
        "There was 1 failure:\n\n1) Tests\\Security\\ExploitTest::testForgedCookie with data set #0 ('admin')\nFailed asserting that true is false.\n",
        "ExploitTest::testForgedCookie",
    ),
    (
        "pest",
        "   FAIL  Tests\\Feature\\ExploitTest\n  \u{2a2f} it accepts a forged cookie\n   FAILED  Tests\\Feature\\ExploitTest > it accepts a forged cookie\n  Failed asserting that true is false.\n",
        "it accepts a forged cookie",
    ),
];

#[test]
fn each_runner_devflow_supports_names_its_red_test() {
    for (runner, said, test) in RED {
        assert!(reached(said, test), "{runner}: {test}");
        assert!(!none_ran(said), "{runner}");
    }
    assert!(reached(RED[3].1, "testForgedCookie with data set #0"));
    assert!(reached(
        RED[2].1,
        "tests/test_exploit.py::TestSession::test_forged_cookie"
    ));
}

#[test]
fn a_harness_error_of_any_runner_is_never_the_hole() {
    let test = "TestSessionForgery";
    for said in [
        // go: the exploit does not compile.
        "# example.test/shop/session [example.test/shop/session.test]\n./exploit_test.go:9:2: undefined: Forge in TestSessionForgery\nFAIL\texample.test/shop/session [build failed]\n",
        // cargo: no test target of that name.
        "error: no test target named `TestSessionForgery` in default-run packages\n",
        // pytest: a fixture that is not there.
        "ERROR tests/test_exploit.py::TestSessionForgery - fixture 'db' not found\n",
        "E       fixture 'db' not found\nFAILED tests/test_exploit.py::TestSessionForgery\n",
        // PHPUnit: the autoloader did not find a class.
        "There was 1 error:\n\n1) Tests\\ExploitTest::TestSessionForgery\nError: Class \"App\\Session\\Forger\" not found\n",
        "PHP Fatal error:  Uncaught Error in TestSessionForgery\n",
    ] {
        assert!(!reached(said, test), "{said}");
    }
}

#[test]
fn a_green_run_that_ran_no_test_refutes_nothing() {
    for said in [
        "testing: warning: no tests to run\nPASS\nok  \texample.test/shop\t0.002s [no tests to run]\n",
        "?   \texample.test/shop/session\t[no test files]\n",
        "running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out\n",
        "No tests executed!\n",
        "collected 0 items\n\n=== no tests ran in 0.01s ===\n",
    ] {
        assert!(none_ran(said), "{said}");
    }
    assert!(!none_ran(
        "running 10 tests\ntest result: ok. 10 passed; 0 failed\n"
    ));
    assert!(!none_ran("ok  \texample.test/shop\t0.002s\n"));
}

#[test]
fn a_cap_hit_is_a_turn_its_time_or_dollars_ended() {
    assert!(cap_hit(crate::agents::TIMED_OUT));
    assert!(cap_hit(crate::agents::BUDGET_SPENT));
    assert!(!cap_hit("not signed in: run claude login"));
}

#[test]
fn the_attacker_is_told_to_prove_a_denial_of_service_by_count_never_by_a_time_limit() {
    for said in [
        "never how long it takes",
        "count what the code does",
        "the calls it makes, the size of what it builds or returns",
        "a small and a large input and assert how the count grows",
        "never an absolute limit in milliseconds",
        "set `\"timing\": true` on its exploit",
    ] {
        assert!(ASK.contains(said), "{said}: {ASK}");
    }
}

/// The attacker is shown, not only told, how a denial of service is proven
/// by count: a concrete test that compares the counts of a small and a
/// large input.
#[test]
fn the_attacker_is_shown_a_count_proof_of_a_denial_of_service() {
    for said in [
        "For example, for a scan that may grow faster than its input",
        "a counter the test reads, or a spy on the call each step makes",
        "1,000 and then 2,000 copies of the hostile input",
        "`expect(steps(2000)).toBeLessThanOrEqual(2.5 * steps(1000))`",
        "on any machine",
    ] {
        assert!(ASK.contains(said), "{said}: {ASK}");
    }
}

/// A hole proven only by time, written again by count, is run on the
/// count's own exploit; once that confirms it, it takes the timing proof
/// in, so the count stands for it. One the count refuted keeps both.
#[test]
fn a_count_proof_takes_in_the_timing_proof_it_confirms() {
    let timed = json!({ "title": "quadratic scan", "class": "redos", "file": "src/scan.ts", "line": 9,
        "status": "confirmed", "cause": "super-linear-work",
        "exploit": { "path": "tests/scan.test.ts", "test": "slow", "timing": true },
        "again": { "item": "card_1", "run": "20261122T142204Z", "id": "h13", "was": "confirmed" } });
    let count = json!({ "id": "h1", "title": "Quadratic scan", "class": "dos", "file": "src/scan.ts", "line": 9,
        "status": "tried", "exploit": { "path": "tests/scan.count.test.ts", "test": "counts",
        "code": "expect(steps(2000)).toBeLessThanOrEqual(2.5 * steps(1000))" } });
    assert!(rewrites_timing(&timed, &count));
    let mut untimed = timed.clone();
    untimed["exploit"]["timing"] = json!(false);
    assert!(!rewrites_timing(&untimed, &count), "only a timing proof");
    let mut clocked = count.clone();
    clocked["exploit"]["timing"] = json!(true);
    assert!(!rewrites_timing(&timed, &clocked), "only a proof by count");

    let mut other = count.clone();
    other["title"] = json!("a deep JSON body overflows the stack");
    other["line"] = json!(12);
    other["status"] = json!("confirmed");
    let mut near = vec![other];
    assert_eq!(
        timing_taken_in(&mut near, vec![timed.clone()]).len(),
        1,
        "another hole a few lines on takes nothing in"
    );
    let mut ran = vec![count.clone()];
    ran[0]["status"] = json!("refuted");
    let kept = timing_taken_in(&mut ran, vec![timed.clone()]);
    assert_eq!(kept.len(), 1, "a count that refuted it takes nothing in");
    ran[0]["status"] = json!("confirmed");
    let kept = timing_taken_in(&mut ran, vec![timed]);
    assert!(kept.is_empty(), "{kept:?}");
    assert_eq!(ran[0]["merged"][0]["id"], "h13", "{:#}", ran[0]);
    assert_eq!(ran[0]["merged"][0]["run"], "20261122T142204Z");
    assert_eq!(ran[0]["cause"], "super-linear-work");
}

#[test]
fn the_attacker_keeps_a_refuted_holes_severity() {
    assert!(
        ASK.contains("a refuted or not_run one keeps the severity it would have"),
        "{ASK}"
    );
}

#[test]
fn the_attacker_names_the_one_fix_of_a_holes_variants() {
    assert!(ASK.contains("variants of one hole"), "{ASK}");
    assert!(ASK.contains("the one change at the root"), "{ASK}");
}

/// An exploit proves by time when its attacker says so, or when its code
/// reads the clock, whatever its attacker said; one that counts does not.
#[test]
fn an_exploit_that_reads_the_clock_proves_by_timing() {
    let tried = |code: &str, timing: bool| {
        json!({ "id": "h1", "title": "a", "severity": "medium", "status": "tried", "reason": "r",
                "exploit": { "path": "tests/a.test.ts", "test": "t", "code": code, "timing": timing } })
    };
    let said = json!({ "hypotheses": [
        tried("const started = Date.now(); run(); expect(Date.now() - started).toBeLessThan(1000);", false),
        tried("import time\nstart = time.perf_counter()", false),
        tried("let mut steps = 0; parse(&input, &mut steps); assert!(steps < 4 * n);", false),
        tried("expect(calls(small) * 4).toBeGreaterThan(calls(large));", true),
    ] });
    let read = read_answer(&said.to_string()).expect("read");
    let timing: Vec<bool> = read["hypotheses"]
        .as_array()
        .expect("hypotheses")
        .iter()
        .map(|one| one["exploit"]["timing"] == true)
        .collect();
    assert_eq!(timing, [true, true, false, true]);
    for clock in CLOCKS {
        assert!(reads_clock(&format!("x = {clock}y)")), "{clock}");
    }
}

/// A proof by time is run [`TIMING_RUNS`] times and stands only when every
/// run agrees; any other proof is run once.
#[test]
fn a_proof_by_timing_stands_only_when_each_of_its_runs_agrees() {
    let red = || ("confirmed", "confirmed", "red".to_owned());
    let green = || ("refuted", "refuted", "green".to_owned());
    let ran = |timing: bool, ends: Vec<(&'static str, &'static str, String)>| {
        let mut ends = ends.into_iter();
        let mut runs = 0;
        let (_, ended, counted) = steady(timing, || {
            runs += 1;
            ((), ends.next().expect("one more run than asked"))
        });
        (ended, counted, runs)
    };
    let (ended, counted, runs) = ran(true, vec![red(), red(), red()]);
    assert_eq!((ended.0, counted, runs), ("confirmed", (3, 3), 3));
    let (ended, counted, _) = ran(true, vec![green(), green(), green()]);
    assert_eq!((ended.0, counted), ("refuted", (3, 0)));
    let (ended, counted, runs) = ran(true, vec![red(), green(), red()]);
    assert_eq!(
        (ended.0, ended.1, counted, runs),
        ("tried", "not_run", (2, 1), 2)
    );
    assert_eq!(
        ended.2,
        "red in 1 of 2 runs: a proof by timing that does not hold steady"
    );
    let (ended, counted, runs) = ran(false, vec![red()]);
    assert_eq!((ended.0, counted, runs), ("confirmed", (1, 1), 1));
    let not_run = || ("tried", "not_run", "it ran past its time".to_owned());
    let (_, counted, runs) = ran(true, vec![not_run()]);
    assert_eq!(
        (counted, runs),
        ((1, 0), 1),
        "one that did not run is not run again"
    );
}

/// A refuted hypothesis ends at `info`, its attacker's severity kept apart
/// as the estimate; one confirmed after all takes it back.
#[test]
fn a_refuted_hypothesis_keeps_its_attackers_estimate_apart() {
    let mut report = json!({ "hypotheses": [
        { "id": "h1", "status": "refuted", "severity": "high", "class": "ssrf", "file": "a.ts" },
        { "id": "h2", "status": "confirmed", "severity": "medium", "class": "ssrf", "file": "b.ts" },
    ] });
    settled(&mut report, &[Severity::High]);
    assert_eq!(report["hypotheses"][0]["severity"], "info");
    assert_eq!(report["hypotheses"][0]["estimated_severity"], "high");
    assert!(report["hypotheses"][1].get("estimated_severity").is_none());
    settled(&mut report, &[Severity::High]);
    assert_eq!(
        report["hypotheses"][0]["estimated_severity"], "high",
        "settled again, the estimate stays the attacker's"
    );
    report["hypotheses"][0]["status"] = json!("confirmed");
    settled(&mut report, &[Severity::High]);
    assert_eq!(report["hypotheses"][0]["severity"], "high");
    assert!(report["hypotheses"][0].get("estimated_severity").is_none());
    assert_eq!(report["verdict"], "request_changes");
}

/// attack.json keeps the families of one root, only confirmed variants in
/// each, and each hypothesis of one names it.
#[test]
fn the_report_keeps_the_families_of_one_root() {
    let one = |id: &str, status: &str, line: u64| json!({ "id": id, "status": status, "severity": "low", "class": "ssrf", "file": "src/block.ts", "line": line });
    let mut report = json!({ "hypotheses": [one("h1", "confirmed", 3), one("h2", "confirmed", 9), one("h3", "refuted", 20)] });
    report["hypotheses"].as_array_mut().expect("list").push(
        json!({ "id": "h4", "status": "confirmed", "severity": "low", "class": "dos", "file": "src/block.ts", "line": 4 }),
    );
    settled(&mut report, &[Severity::High]);
    assert_eq!(
        report["families"],
        json!([{ "id": "f1", "class": "ssrf", "file": "src/block.ts", "cause": null,
                 "variants": ["h1", "h2"], "confirmed": 2, "carried": 0 }])
    );
    assert!(
        report["hypotheses"][2].get("family").is_none(),
        "a refuted one is no variant"
    );
    assert!(report["hypotheses"][3].get("family").is_none());
    report["hypotheses"][1]["class"] = json!("dos");
    report["hypotheses"][2]["class"] = json!("authz");
    settled(&mut report, &[Severity::High]);
    assert_eq!(report["families"].as_array().map(Vec::len), Some(1));
    assert_eq!(report["families"][0]["variants"], json!(["h2", "h4"]));
    assert_eq!(report["hypotheses"][1]["family"], "f1");
    assert!(
        report["hypotheses"][0].get("family").is_none(),
        "a family settled again leaves none stale"
    );
}

/// A hypothesis merged into another is named on its trail by an id and a
/// run: the run that kept it and its id there, or this run and the id its
/// attacker gave it, kept apart as `said_as` so it never reads as one of the
/// report's own ids.
#[test]
fn a_merged_hypothesis_is_named_by_its_id_and_its_run() {
    let mut kept = json!({ "title": "a", "class": "ssrf", "file": "a.ts", "line": 3 });
    let earlier = json!({ "title": "b", "class": "ssrf", "file": "a.ts", "line": 4,
        "again": { "item": "card_1", "run": "20261121T031245Z", "id": "h2", "was": "confirmed" } });
    let own = json!({ "id": "h7", "title": "c", "class": "ssrf", "file": "a.ts", "line": 5, "found_by": ["claude/large"] });
    merge_into(&mut kept, &earlier);
    merge_into(&mut kept, &own);
    let mut list = vec![kept];
    runs_named(&mut list, "20261122T142204Z");
    let named: Vec<(&str, &str, &str)> = list[0]["merged"]
        .as_array()
        .expect("merged")
        .iter()
        .map(|one| {
            (
                one["id"].as_str().unwrap_or("-"),
                one["said_as"].as_str().unwrap_or("-"),
                one["run"].as_str().unwrap_or("-"),
            )
        })
        .collect();
    assert_eq!(
        named,
        [
            ("h2", "-", "20261121T031245Z"),
            ("-", "h7", "20261122T142204Z")
        ]
    );
    assert_eq!(list[0]["merged"][0]["again"]["was"], "confirmed");
}

#[test]
fn the_hypothesis_kept_says_what_it_took_in() {
    let h = |line: i64, class: &str, title: &str, exploit: bool| {
        let mut one = json!({ "id": "h1", "file": "src/db.ts", "line": line, "class": class, "title": title, "status": "tried" });
        if exploit {
            one["exploit"] = json!({ "path": "tests/x.ts", "test": "x", "code": "secret code" });
        }
        one
    };
    let kept = consolidated(vec![
        (
            "claude/large".to_owned(),
            vec![h(7, "tls", "no CA check", false)],
        ),
        (
            "codex/default".to_owned(),
            vec![h(8, "ssl", "rejectUnauthorized", true)],
        ),
        (
            "gemini/default".to_owned(),
            vec![h(7, "transport", "any peer", false)],
        ),
    ]);
    assert_eq!(kept.len(), 1, "{kept:#?}");
    let merged = kept[0]["merged"].as_array().expect("merged");
    let titles: Vec<&str> = merged
        .iter()
        .filter_map(|one| one["title"].as_str())
        .collect();
    assert_eq!(
        titles,
        ["no CA check", "any peer"],
        "the exploit's stands, the rest are its trail"
    );
    assert_eq!(merged[0]["found_by"], json!(["claude/large"]));
    assert_eq!(merged[0]["said_as"], "h1", "the id its attacker gave it");
    assert!(
        merged[0].get("id").is_none(),
        "never a final id: {merged:#?}"
    );
    assert!(
        !kept[0]["merged"].to_string().contains("secret code"),
        "never an exploit"
    );
}

/// An exploit an earlier run kept that reads the clock proves by timing
/// when it is run again, though its attacker never said so.
#[test]
fn an_earlier_exploit_that_reads_the_clock_is_run_again_as_timing() {
    let run = tempfile::tempdir().expect("run");
    let keep = |name: &str, code: &str| {
        std::fs::create_dir_all(run.path().join("exploits").join(name)).expect("folder");
        std::fs::write(run.path().join(format!("exploits/{name}/a.test.ts")), code).expect("code");
    };
    keep(
        "h1",
        "const t = performance.now(); run(); expect(performance.now() - t).toBeLessThan(1000);",
    );
    keep(
        "h2",
        "const steps = run(); expect(steps).toBeLessThan(4 * n);",
    );
    let kept = |id: &str| {
        json!({ "id": id, "status": "confirmed", "title": "slow", "class": "redos", "file": "a.ts", "line": 1,
                "exploit": { "path": "tests/a.test.ts", "test": "t", "saved": format!("exploits/{id}/a.test.ts") } })
    };
    let again = left_open(&kept("h1"), run.path(), "card_1", "20261121T031245Z").expect("open");
    assert_eq!(again["exploit"]["timing"], true, "{again:#}");
    let again = left_open(&kept("h2"), run.path(), "card_1", "20261121T031245Z").expect("open");
    assert!(again["exploit"].get("timing").is_none(), "{again:#}");
}

/// One attacker's hypothesis merged into another's in this run keeps the id
/// its attacker gave it apart from the report's own ids: the report lists it
/// under "merged in this run", never as one of an earlier run.
#[test]
fn a_merge_in_this_run_keeps_the_attackers_id_apart_from_the_final_ones() {
    let one = |id: &str, class: &str, file: &str, line: u64, title: &str| {
        json!({ "id": id, "title": title, "class": class, "file": file, "line": line,
            "severity": "low", "status": "confirmed", "verified": { "by": "sandbox" } })
    };
    let mut kept = merged_across(vec![
        (
            "claude/large".to_owned(),
            vec![
                one("h1", "ssrf", "src/fetch.ts", 5, "any address is fetched"),
                one("h2", "xss", "src/page.ts", 40, "markup is stored live"),
            ],
        ),
        (
            "codex/default".to_owned(),
            vec![one(
                "h2",
                "ssrf",
                "src/fetch.ts",
                6,
                "a private address is fetched",
            )],
        ),
    ]);
    runs_named(&mut kept, "20261122T195432Z");
    for (at, one) in kept.iter_mut().enumerate() {
        one["id"] = json!(format!("h{}", at + 1));
    }
    let report = json!({ "run": "20261122T195432Z", "hypotheses": kept });
    let known = crate::attack_report::Known::of(&report);
    let shown = crate::attack_report::json_of(&report, &known);
    let merged = &shown["hypotheses"][0]["merged"];
    assert_eq!(merged[0]["said_as"], "h2", "{shown:#}");
    assert_eq!(merged[0]["by"], "codex", "{shown:#}");
    assert!(merged[0]["id"].is_null(), "{shown:#}");
    let md = crate::attack_report::markdown(&report, &known);
    let this_run = md
        .split("### Merged in this run")
        .nth(1)
        .expect("its own heading");
    assert!(
        this_run.contains("- h1 took in what codex numbered h2 (ssrf, line 6)"),
        "{md}"
    );
    assert!(!md.contains("h2 of run"), "{md}");
    assert!(!md.contains("### From earlier runs"), "{md}");
}

/// What a hypothesis took in is said once each, named by the run and id
/// that kept it: an older report's entry with no id is named by its
/// `again`, and the same hole taken in by two paths is said once.
#[test]
fn what_a_hypothesis_took_in_is_said_once_and_never_without_an_id() {
    let mut kept = json!({ "title": "pg TLS off", "class": "crypto", "file": "src/db.ts", "line": 14,
        "again": { "item": "card_1", "run": "20261122T185109Z", "id": "h18", "was": "confirmed" } });
    let again =
        |run: &str, id: &str| json!({ "item": "card_1", "run": run, "id": id, "was": "confirmed" });
    let gone = json!({ "title": "pg TLS", "class": "tls", "file": "src/db.ts", "line": 14,
        "again": again("20261122T142204Z", "h19"),
        "merged": [
            { "id": null, "run": "20261122T142204Z", "class": "crypto", "line": 14,
              "again": again("20261121T031245Z", "h15") },
            { "id": "h15", "run": "20261121T031245Z", "class": "crypto", "line": 14,
              "again": again("20261121T031245Z", "h15") },
            { "id": null, "run": "20261122T142204Z", "class": "tls", "line": 14,
              "again": again("20261121T031245Z", "h18") },
            { "id": null, "run": null, "class": "tls", "line": 14 },
        ] });
    merge_into(&mut kept, &gone);
    let named: Vec<(String, String)> = kept["merged"]
        .as_array()
        .expect("merged")
        .iter()
        .map(|one| (one["run"].to_string(), one["id"].to_string()))
        .collect();
    assert_eq!(
        named,
        [
            ("\"20261121T031245Z\"".to_owned(), "\"h15\"".to_owned()),
            ("\"20261121T031245Z\"".to_owned(), "\"h18\"".to_owned()),
            ("\"20261122T142204Z\"".to_owned(), "\"h19\"".to_owned()),
        ],
        "{kept:#}"
    );
}

/// A count proof that takes in a hole an earlier run proved only by time is
/// that hole run again: it carries its `again`, not only its trail.
#[test]
fn a_count_proof_that_takes_in_a_timing_one_carries_its_again() {
    let mut hypotheses = vec![
        json!({ "id": "h1", "title": "Quadratic scan", "file": "src/scan.ts",
        "line": 529, "class": "redos", "status": "confirmed",
        "exploit": { "path": "tests/count.test.ts", "test": "count", "code": "steps" } }),
    ];
    let timed = json!({ "id": "again-1", "title": "quadratic scan", "file": "src/scan.ts", "line": 529,
        "class": "redos", "status": "confirmed", "exploit": { "timing": true, "code": "Date.now(" },
        "again": { "item": "card_1", "run": "20261122T185109Z", "id": "h12", "was": "confirmed" } });
    let left = timing_taken_in(&mut hypotheses, vec![timed]);
    assert!(left.is_empty());
    assert_eq!(
        hypotheses[0]["again"],
        json!({ "item": "card_1", "run": "20261122T185109Z", "id": "h12", "was": "confirmed" })
    );
    assert_eq!(hypotheses[0]["merged"][0]["id"], "h12");
}

/// A class is kept in attack.json by devflow's name for it, as the reports
/// show it, and the attacker's own word beside it when it differs.
#[test]
fn a_class_is_kept_by_devflows_name_with_the_attackers_word_beside_it() {
    let said = r#"{ "hypotheses": [
        { "id": "h1", "title": "markup stored live", "class": "Stored XSS", "file": "src/a.ts", "line": 3,
          "severity": "low", "status": "refuted", "reason": "escaped" },
        { "id": "h2", "title": "ssrf", "class": "ssrf", "file": "src/a.ts", "line": 9,
          "severity": "low", "status": "refuted", "reason": "blocked" } ] }"#;
    let answer = read_answer(said).expect("answer");
    assert_eq!(answer["hypotheses"][0]["class"], "xss");
    assert_eq!(answer["hypotheses"][0]["class_said"], "Stored XSS");
    assert_eq!(answer["hypotheses"][1]["class"], "ssrf");
    assert!(answer["hypotheses"][1].get("class_said").is_none());
}

/// The threat model is written again only when it should change: the
/// attacker is told an empty one keeps the project's.
#[test]
fn the_attacker_writes_the_threat_model_only_when_it_should_change() {
    assert!(ASK.contains("an empty string when the threat model above still reads right"));
}

/// A hole carried past the cap, confirmed with an exploit of its own, is
/// taken in by an attacker's confirmed hypothesis at its place only when it
/// is the same hole: its title, or its cause at its line. Another variant
/// beside it stays carried, to run next time.
#[test]
fn a_carried_variant_is_taken_in_only_as_the_same_hole() {
    let hole = |title: &str, line: u64, test: &str| {
        json!({ "title": title, "class": "redos", "cause": "super-linear-work", "file": "src/a.ts",
            "line": line, "severity": "low", "status": "confirmed", "carried": "cap",
            "again": { "item": "i", "run": "20261118T120000Z", "id": "h2", "was": "confirmed" },
            "exploit": { "path": "tests/a.test.ts", "test": test, "code": format!("exit 1 # {test}") } })
    };
    let own = || {
        let mut one = hole("unclosed script tags", 529, "script");
        one["status"] = json!("confirmed");
        one["carried"] = Value::Null;
        one["again"] = Value::Null;
        one
    };
    let mut hypotheses = vec![own()];
    let kept = carried_taken_in(
        &mut hypotheses,
        vec![hole("the generic tag pattern", 531, "tag")],
    );
    assert_eq!(kept.len(), 1, "a variant two lines on stays carried");
    assert!(hypotheses[0]["merged"].is_null());
    let mut hypotheses = vec![own()];
    let kept = carried_taken_in(
        &mut hypotheses,
        vec![hole("script tags, said again", 529, "again")],
    );
    assert!(kept.is_empty(), "its cause at its line: one hole");
    assert_eq!(hypotheses[0]["merged"][0]["id"], "h2");
    // One whose exploit is not kept leaves nothing unrun: it is taken in.
    let mut missing = hole("the generic tag pattern", 531, "tag");
    missing["exploit"] = json!({});
    let mut hypotheses = vec![own()];
    assert!(carried_taken_in(&mut hypotheses, vec![missing]).is_empty());
}

/// An attacker's own exploit of another variant beside a hole run again is
/// run; one that says that hole again (its title, its exploit, or its line
/// with its cause) is taken in.
#[test]
fn an_attackers_variant_beside_a_hole_run_again_is_another_one() {
    let at = |title: &str, line: u64, test: &str, cause: Option<&str>| {
        let mut one = json!({ "title": title, "class": "redos", "file": "src/a.ts", "line": line,
            "status": "confirmed", "exploit": { "path": "tests/a.test.ts", "test": test, "code": format!("exit 1 # {test}") } });
        if let Some(cause) = cause {
            one["cause"] = json!(cause);
        }
        one
    };
    let had = at(
        "unclosed script tags",
        529,
        "script",
        Some("super-linear-work"),
    );
    let cause = Some("super-linear-work");
    assert!(variant_apart(
        &had,
        &at("the generic tag pattern", 531, "tag", cause)
    ));
    assert!(!variant_apart(
        &had,
        &at("unclosed script tags", 531, "tag", cause)
    ));
    assert!(!variant_apart(&had, &at("said again", 529, "again", cause)));
    assert!(!variant_apart(&had, &at("said again", 529, "again", None)));
    assert!(variant_apart(
        &had,
        &at("said again", 529, "again", Some("unbounded-input"))
    ));
    assert!(!variant_apart(
        &had,
        &at("another title", 531, "script", cause)
    ));
    let mut no_exploit = at("the generic tag pattern", 531, "tag", cause);
    no_exploit["exploit"] = json!({});
    assert!(
        !variant_apart(&had, &no_exploit),
        "nothing of its own to run"
    );
}
