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
