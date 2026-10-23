use serde_json::json;

use super::*;

fn plan() -> Value {
    json!([
        {
            "key": "s1",
            "title": "[devflow] Cards are indexed by their body",
            "build": "Typing a word finds the cards whose body holds it.",
            "criteria": ["a word in a body finds its card", "  an empty   query finds nothing "],
            "files": ["crates/core/src/store/search_index.rs"],
            "verify": "cargo test -p devpit-core search_index",
            "depends_on": []
        },
        { "key": "s2", "title": "The search box lists them", "depends_on": ["s1"] },
        { "key": "s3", "title": "Matches are highlighted", "depends_on": ["s2", "s1"] }
    ])
}

#[test]
fn a_plan_is_read_trimmed_and_its_cards_wait_by_index() {
    let slices = read(&plan()).expect("a plan");
    assert_eq!(slices[0].title, "Cards are indexed by their body");
    assert_eq!(slices[0].criteria[1], "an empty query finds nothing");
    assert_eq!(waits_on(&slices), [vec![], vec![0], vec![1, 0]]);
    assert_eq!(title(&slices[1]), "[devflow] The search box lists them");
}

#[test]
fn a_plan_that_could_never_start_or_does_not_hold_together_is_refused() {
    let mut circle = plan();
    circle[0]["depends_on"] = json!(["s3"]);
    let refused = read(&circle).expect_err("a circle");
    assert!(refused.contains("circle"), "{refused}");

    let mut missing = plan();
    missing[1]["depends_on"] = json!(["s9"]);
    assert!(read(&missing).expect_err("a missing key").contains("`s9`"));

    let mut twice = plan();
    twice[2]["key"] = json!("s1");
    assert!(read(&twice).expect_err("a key twice").contains("twice"));

    let mut itself = plan();
    itself[1]["depends_on"] = json!(["s2"]);
    assert!(read(&itself).is_err());

    assert!(read(&json!([])).is_err());
    assert!(read(&json!([{ "key": "s1" }])).is_err());
    let mut untitled = plan();
    untitled[0]["title"] = json!("[devflow]  ");
    assert!(read(&untitled).is_err());
}

#[test]
fn depends_on_names_a_card_of_another_epic_by_its_id_or_number() {
    let mut other = plan();
    other[1]["depends_on"] = json!(["s1", "#42", "card_01ABC", "7"]);
    let slices = read(&other).expect("a plan waiting on items outside it");
    assert_eq!(outside(&slices, &slices[1]), ["#42", "card_01ABC", "7"]);
    assert_eq!(waits_on(&slices)[1], [0]);

    for wrong in ["#", "#4x", "4x"] {
        other[1]["depends_on"] = json!([wrong]);
        assert!(read(&other).is_err(), "{wrong}");
    }
}

#[test]
fn a_cards_body_reads_on_its_own_and_its_criteria_are_checkboxes() {
    let slices = read(&plan()).expect("a plan");
    let body = body(&slices[0]);
    assert!(body.starts_with("Typing a word finds the cards whose body holds it.\n\n## Acceptance criteria\n- [ ] a word"), "{body}");
    assert!(
        body.contains("## Likely files\n- `crates/core/src/store/search_index.rs`"),
        "{body}"
    );
    assert!(
        body.ends_with("## Verify\n```sh\ncargo test -p devpit-core search_index\n```"),
        "{body}"
    );
    let read_back: Vec<String> = criteria::criteria(&body)
        .into_iter()
        .map(|one| one.text)
        .collect();
    assert_eq!(read_back, slices[0].criteria);
    // A card with only a title has an empty body, not empty headings.
    assert_eq!(super::body(&slices[1]), "");
}
