use serde_json::json;

use super::*;

fn report(cost: f64, statuses: &[(&str, &str)]) -> Value {
    json!({
        "attackers": [{ "agent": "claude", "model": "large", "cost_usd": cost, "duration_ms": 1000 }],
        "hypotheses": statuses.iter().map(|(status, from)| json!({ "status": status, "from": from })).collect::<Vec<_>>(),
    })
}

#[test]
fn a_runs_numbers_say_what_it_cost_per_confirmed_hole_and_what_the_review_missed() {
    let said = of_report(&report(
        3.0,
        &[
            ("confirmed", "attack"),
            ("confirmed", "r0"),
            ("refuted", "attack"),
            ("not_run", "attack"),
        ],
    ));
    assert_eq!(said["confirmed"], 2);
    assert_eq!(said["refuted"], 1);
    assert_eq!(said["not_run"], 1);
    assert_eq!(said["cost_usd"], 3.0);
    assert_eq!(said["cost_per_confirmed"], 1.5);
    assert_eq!(said["missed_by_review"], 1, "only what the attack started");
    assert_eq!(said["by_attacker"][0]["agent"], "claude");
    assert!(of_report(&report(2.0, &[]))
        .get("cost_per_confirmed")
        .is_some_and(Value::is_null));
}

#[test]
fn the_ledger_keeps_the_last_word_on_each_run_and_adds_up_the_month() {
    let dir = tempfile::tempdir().expect("dir");
    let home = dir.path();
    record(
        home,
        "card_1",
        "20261119T100000Z",
        &report(2.0, &[("tried", "attack")]),
    )
    .expect("one");
    record(
        home,
        "card_1",
        "20261119T100000Z",
        &report(2.0, &[("confirmed", "attack")]),
    )
    .expect("again");
    record(home, "card_2", "20261020T100000Z", &report(5.0, &[])).expect("last month");
    let runs = ledger(home);
    assert_eq!(runs.len(), 2);
    let first = runs
        .iter()
        .find(|one| one["item"] == "card_1")
        .expect("card_1");
    assert_eq!(first["metrics"]["confirmed"], 1, "the later line stands");
    assert_eq!(spent_in(&runs, "202611"), 2.0);
    assert_eq!(spent_in(&runs, "202610"), 5.0);
    let project = project(&runs, AttackRun::Sensitive);
    assert_eq!(project["runs"], 2);
    assert_eq!(project["cost_usd"], 7.0);
    assert_eq!(project["cost_per_confirmed"], 7.0);
}

#[test]
fn enough_runs_suggest_a_run_mode() {
    assert!(
        suggestion(9, 0, 0, AttackRun::PerItem).is_none(),
        "too few to say"
    );
    assert!(suggestion(10, 0, 0, AttackRun::PerItem)
        .expect("said")
        .contains("consider sensitive"));
    assert!(suggestion(12, 3, 2, AttackRun::Sensitive)
        .expect("said")
        .contains("consider per-item"));
    assert!(suggestion(12, 3, 0, AttackRun::Sensitive).is_none());
}

#[test]
fn a_ledger_past_its_ceiling_still_counts_its_newest_runs() {
    let dir = tempfile::tempdir().expect("dir");
    let filler = format!("{}\n", "x".repeat(1023));
    let old: String = filler.repeat((MOST_LEDGER / 1024 + 64) as usize);
    std::fs::write(dir.path().join(LEDGER), old).expect("big");
    record(dir.path(), "card_1", "20261119T100000Z", &report(9.0, &[])).expect("newest");
    assert_eq!(
        spent_in(&ledger(dir.path()), "202611"),
        9.0,
        "the month is still counted"
    );
}

#[cfg(unix)]
#[test]
fn the_ledger_is_never_reached_through_a_link_out_of_its_home() {
    let dir = tempfile::tempdir().expect("dir");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let outside = dir.path().join("outside.jsonl");
    std::fs::write(&outside, "").expect("outside");
    std::os::unix::fs::symlink(&outside, home.join(LEDGER)).expect("link");
    assert!(record(&home, "card_1", "20261119T100000Z", &report(1.0, &[])).is_err());
    assert_eq!(
        std::fs::read_to_string(&outside).expect("outside"),
        "",
        "nothing written out"
    );
}
