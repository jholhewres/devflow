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
    for outside in ["../a.test.ts", "/etc/passwd", "tests/../../a", ""] {
        assert!(exploit_path(outside).is_err(), "{outside}");
    }
}
