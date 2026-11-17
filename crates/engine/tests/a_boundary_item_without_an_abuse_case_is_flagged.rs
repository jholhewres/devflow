//! A plan item that crosses a trust boundary, by its files or by the plan's
//! word, says how it could be abused; one that does not is flagged, and the
//! plan is still made.

use devflow_engine::plan;
use devflow_engine::scale::SENSITIVE;
use serde_json::json;

fn sensitive() -> Vec<String> {
    SENSITIVE.iter().map(|one| (*one).to_owned()).collect()
}

#[test]
fn a_boundary_item_without_an_abuse_case_is_flagged() {
    let slices = plan::read(&json!([
        {
            "key": "login",
            "title": "Sessions expire after an hour",
            "criteria": ["a session older than an hour is refused"],
            "files": ["src/auth/session.rs"]
        },
        {
            "key": "webhook",
            "title": "Webhooks are received",
            "criteria": ["a delivery is stored"],
            "files": ["src/hooks/receive.rs"],
            "boundary": true
        },
        {
            "key": "guarded",
            "title": "Passwords are rehashed on login",
            "criteria": ["an old hash is replaced"],
            "abuse": ["a login with a forged session cookie is refused"],
            "files": ["src/auth/password.rs"]
        },
        {
            "key": "copy",
            "title": "The footer says the year",
            "criteria": ["the footer shows 2026"],
            "files": ["src/ui/footer.rs"]
        }
    ]))
    .expect("a plan is made, flagged or not");

    let flagged = plan::unguarded(&slices, &sensitive());
    let keys: Vec<&str> = flagged.iter().map(|(key, _)| key.as_str()).collect();
    assert_eq!(keys, ["login", "webhook"]);
    assert!(flagged[0].1.contains("src/auth/session.rs"), "{flagged:?}");
    assert!(flagged[1].1.contains("the plan marks it"), "{flagged:?}");
    assert!(plan::unguarded_said(&flagged)[0].contains("abuse"));
}

#[test]
fn an_abuse_case_is_a_criterion_the_gate_holds_the_item_to() {
    let slices = plan::read(&json!([{
        "key": "guarded",
        "title": "Passwords are rehashed on login",
        "abuse": ["Abuse case: a forged session cookie is refused"],
        "files": ["src/auth/password.rs"]
    }]))
    .expect("a plan");
    let body = plan::body(&slices[0]);
    let read: Vec<String> = devflow_engine::criteria::criteria(&body)
        .into_iter()
        .map(|one| one.text)
        .collect();
    assert_eq!(read, ["Abuse case: a forged session cookie is refused"]);
}

#[test]
fn a_plan_said_with_no_boundary_reads_and_renders_as_before() {
    let slices = plan::read(&json!([{
        "key": "s1",
        "title": "The footer says the year",
        "criteria": ["the footer shows 2026"]
    }]))
    .expect("a plan");
    assert_eq!(
        serde_json::to_value(&slices[0]).expect("json"),
        json!({
            "key": "s1", "title": "The footer says the year", "build": "",
            "criteria": ["the footer shows 2026"], "files": [], "verify": "", "depends_on": []
        })
    );
    assert_eq!(
        plan::body(&slices[0]),
        "## Acceptance criteria\n- [ ] the footer shows 2026"
    );
}
