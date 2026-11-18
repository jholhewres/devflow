use serde_json::json;

use super::*;

const FILE: &str = "\
# Our flow. Ask Ana before changing the gate.
version: 2
enabled: false   # flipped by the app
ours: { kept: true }   # devflow does not read this
stages:
  - uses: builtin/plan
    approve: person
  - uses: builtin/execution
    # the checks we trust
    checks:
      - name: unit
        run: make test
review:
  block_on: [critical]

  # who reads it
  reviewers:
  - agent: claude
    persona: devflow-security
decisions:
  mode: shadow # for now
";

fn edited(path: &str, value: serde_json::Value) -> String {
    set(FILE, path, &value).unwrap_or_else(|| panic!("{path} is edited in place"))
}

#[test]
fn a_word_is_swapped_where_it_stands() {
    assert_eq!(
        edited("enabled", json!(true)),
        FILE.replace("enabled: false   #", "enabled: true   #")
    );
    assert_eq!(
        edited("stages.plan.approve", json!("none")),
        FILE.replace("approve: person", "approve: none")
    );
}

#[test]
fn a_new_key_goes_after_its_map_s_last_one() {
    assert_eq!(
        edited("decisions.provider", json!("openrouter")),
        FILE.replace(
            "  mode: shadow # for now\n",
            "  mode: shadow # for now\n  provider: openrouter\n"
        )
    );
    assert_eq!(
        edited("stages.plan.model", json!("large")),
        FILE.replace(
            "    approve: person\n",
            "    approve: person\n    model: large\n"
        )
    );
}

#[test]
fn a_new_map_is_written_whole_under_the_nearest_one_there() {
    assert_eq!(
        edited("review.attack.run", json!("release")),
        FILE.replace(
            "    persona: devflow-security\n",
            "    persona: devflow-security\n  attack:\n    run: release\n"
        )
    );
}

#[test]
fn a_list_is_replaced_and_every_comment_around_it_stays() {
    let text = edited("review.block_on", json!(["critical", "high"]));
    assert_eq!(
        text,
        FILE.replace(
            "  block_on: [critical]\n",
            "  block_on:\n    - critical\n    - high\n"
        )
    );
    let text = edited(
        "stages.execution.checks",
        json!([{ "name": "unit", "run": "make test" }, { "name": "lint", "run": "make lint" }]),
    );
    assert!(text.contains("    # the checks we trust\n    checks:\n      - name: unit\n        run: make test\n      - name: lint\n        run: make lint\nreview:"), "{text}");
}

#[test]
fn a_compact_list_under_its_key_is_part_of_the_key() {
    let text = edited("review.reviewers", json!([]));
    assert!(
        text.contains("  # who reads it\n  reviewers: []\ndecisions:"),
        "{text}"
    );
}

#[test]
fn a_key_removed_takes_its_lines_and_an_emptied_map_its_own() {
    assert_eq!(
        edited("decisions.mode", serde_json::Value::Null),
        FILE.replace("decisions:\n  mode: shadow # for now\n", "")
    );
    assert_eq!(
        edited("review.block_on", serde_json::Value::Null),
        FILE.replace("  block_on: [critical]\n", "")
    );
    assert_eq!(edited("nothing.here", serde_json::Value::Null), FILE);
}

#[test]
fn what_cannot_be_edited_in_place_is_said() {
    // Inside a flow map, and an item's first key, which shares the dash's line.
    assert_eq!(set(FILE, "ours.other", &json!(1)), None);
    assert_eq!(
        set(FILE, "stages.plan.uses", &serde_json::Value::Null),
        None
    );
    assert_eq!(set("not: [valid", "a", &json!(1)), None);
}

#[test]
fn a_text_with_no_last_newline_is_edited_all_the_same() {
    assert_eq!(
        set("version: 2\nenabled: false", "enabled", &json!(true)).as_deref(),
        Some("version: 2\nenabled: true\n")
    );
    assert_eq!(
        set("version: 2", "review.consolidate", &json!("none")).as_deref(),
        Some("version: 2\nreview:\n  consolidate: none\n")
    );
}

#[test]
fn a_value_that_is_not_a_plain_word_is_quoted() {
    assert_eq!(
        set("version: 2\n", "note", &json!("yes: no # not a comment")).as_deref(),
        Some("version: 2\nnote: \"yes: no # not a comment\"\n")
    );
}
