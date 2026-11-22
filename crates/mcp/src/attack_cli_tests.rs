use devflow_engine::config::Severity;
use serde_json::json;

use super::{ci_exit, range_ends};

#[test]
fn a_release_range_exits_1_on_a_confirmed_exploit_in_block_on_and_0_below_it() {
    let report = json!({ "hypotheses": [
        { "id": "h1", "status": "confirmed", "severity": "high", "class": "ssrf" },
        { "id": "h2", "status": "refuted", "severity": "critical" },
    ] });
    assert_eq!(ci_exit(&report, &[Severity::Critical, Severity::High]), 1);
    assert_eq!(ci_exit(&report, &[Severity::Critical]), 0, "below block_on");
    assert_eq!(ci_exit(&json!({ "hypotheses": [] }), &[Severity::High]), 0);
}

#[test]
fn a_release_range_is_a_dot_dot_or_three_dots() {
    assert_eq!(range_ends("v0.5.2..HEAD"), Some(("v0.5.2", "HEAD")));
    assert_eq!(range_ends("main...feature"), Some(("main", "feature")));
    for not in ["HEAD", "..HEAD", "v1..", "a..b..c"] {
        assert_eq!(range_ends(not), None, "{not}");
    }
}
