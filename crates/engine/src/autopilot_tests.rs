use super::*;

fn card(id: &str, blocked_by: &[(&str, bool)], standing: Standing) -> Planned {
    Planned {
        id: id.to_owned(),
        title: format!("card {id}"),
        blocked_by: blocked_by
            .iter()
            .map(|(by, done)| ((*by).to_owned(), *done))
            .collect(),
        standing,
    }
}

/// Listed out of order on purpose: c waits on b, which waits on a.
fn plan(a: Standing, b: Standing, c: Standing) -> Vec<Planned> {
    let done = |standing: &Standing| *standing == Standing::Done;
    let (a_done, b_done) = (done(&a), done(&b));
    vec![
        card("c", &[("b", b_done)], c),
        card("a", &[], a),
        card("b", &[("a", a_done)], b),
    ]
}

#[test]
fn three_dependent_cards_run_in_the_order_their_blockers_allow() {
    use Standing::*;
    let order: Vec<String> = ordered(&plan(Waiting, Waiting, Waiting))
        .expect("no cycle")
        .iter()
        .map(|card| card.id.clone())
        .collect();
    assert_eq!(order, ["a", "b", "c"]);

    assert_eq!(
        next(&plan(Waiting, Waiting, Waiting), false),
        Next::Start("a".into())
    );
    assert_eq!(
        next(&plan(Working, Waiting, Waiting), false),
        Next::Working("a".into())
    );
    assert_eq!(
        next(&plan(Done, Waiting, Waiting), false),
        Next::Start("b".into())
    );
    assert_eq!(
        next(&plan(Done, Done, Waiting), false),
        Next::Start("c".into())
    );
    assert_eq!(next(&plan(Done, Done, Finished), false), Next::Done);
}

#[test]
fn it_stops_at_the_approval_point_and_never_starts_past_it() {
    use Standing::*;
    // b waits on a, which passed its gate but is not done: the person checks it.
    let Next::Approve { card, why } = next(&plan(Finished, Waiting, Waiting), false) else {
        panic!("it went past the approval point")
    };
    assert_eq!(card, "a");
    assert!(why.contains("move it to done"), "{why}");
    // A flow that asks the person to approve each card stops after every one.
    assert!(matches!(
        next(&plan(Done, Finished, Waiting), true),
        Next::Approve { card, .. } if card == "b"
    ));
}

#[test]
fn a_session_stopped_on_the_person_or_a_cycle_is_a_blocker() {
    use Standing::*;
    let stuck = next(
        &plan(Stuck("it asked a question".into()), Waiting, Waiting),
        false,
    );
    assert_eq!(
        stuck,
        Next::Blocked {
            card: "a".into(),
            why: "it asked a question".into()
        }
    );
    let cycle = vec![
        card("x", &[("y", false)], Waiting),
        card("y", &[("x", false)], Waiting),
    ];
    assert!(matches!(next(&cycle, false), Next::Blocked { .. }));
    let outside = vec![card("x", &[("elsewhere", false)], Waiting)];
    assert!(
        matches!(next(&outside, false), Next::Blocked { why, .. } if why.contains("not part of this plan"))
    );
}
