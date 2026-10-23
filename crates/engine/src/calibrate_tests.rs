use super::*;

fn labelled(score: f64, outcome: &str, truth: bool) -> Labelled {
    Labelled {
        score: Some(score),
        outcome: outcome.to_owned(),
        truth,
    }
}

/// Four the person failed, scored at most 0.45, and four they passed, from
/// 0.8: every line from 0.5 to 0.8 agrees with all eight, so the middle of
/// that stretch is suggested, with grey just under it.
#[test]
fn a_clean_split_suggests_the_middle_of_the_lines_that_agree() {
    let samples = [
        (0.2, false),
        (0.3, false),
        (0.35, false),
        (0.45, false),
        (0.8, true),
        (0.85, true),
        (0.9, true),
        (0.95, true),
    ];
    let suggested = suggested(&samples).expect("enough labels");
    assert!((suggested.min - 0.65).abs() < 1e-9, "{suggested:?}");
    assert_eq!(suggested.grey, Some(0.6));
    assert!((suggested.accuracy - 1.0).abs() < 1e-9);
}

/// A rubric whose line sat too low: it passed what the person then
/// reopened. Its accuracy says so, and the line suggested is higher.
#[test]
fn a_line_set_too_low_shows_in_its_accuracy_and_the_suggestion_moves_it_up() {
    let mut all = vec![
        labelled(0.75, "pass", false),
        labelled(0.72, "pass", false),
        labelled(0.78, "pass", false),
        labelled(0.3, "fail", false),
        labelled(0.66, "grey", false),
    ];
    for score in [0.9, 0.92, 0.95, 0.97] {
        all.push(labelled(score, "pass", true));
    }
    let calibration = calibrated(&all);
    assert_eq!(calibration.labelled, 9);
    assert_eq!(calibration.grey, 1);
    assert_eq!(calibration.decided, 8);
    assert_eq!(calibration.agreed, 5);
    assert_eq!(calibration.accuracy, Some(5.0 / 8.0));
    let suggested = calibration.suggested.expect("suggested");
    assert!(
        suggested.min > 0.78 && suggested.min <= 0.9,
        "{suggested:?}"
    );
    assert!((suggested.accuracy - 1.0).abs() < 1e-9);
}

#[test]
fn too_few_labels_suggest_nothing_and_say_how_many_there_are() {
    let calibration = calibrated(&[
        labelled(0.9, "pass", true),
        labelled(0.2, "fail", true),
        Labelled {
            score: None,
            outcome: "skipped".into(),
            truth: true,
        },
    ]);
    assert_eq!(calibration.labelled, 2, "a skip was never judged");
    assert_eq!(calibration.accuracy, Some(0.5));
    assert_eq!(calibration.suggested, None);
    assert!(calibration
        .note
        .is_some_and(|note| note.starts_with("2 labelled so far")));
    assert_eq!(calibrated(&[]).accuracy, None);
}

/// Enforce waits for twenty findings the person confirmed, and then for Jev
/// to have failed at most one in ten of them; what the person called false
/// and what was left grey do not count against it.
#[test]
fn enforce_is_refused_below_the_bar_of_confirmed_findings() {
    let confirmed = |failed: usize, of: usize| -> Vec<Labelled> {
        (0..of)
            .map(|at| labelled(0.9, if at < failed { "fail" } else { "pass" }, true))
            .collect()
    };
    let too_few = enforceable(&confirmed(0, ENFORCE_AFTER - 1)).expect_err("too few");
    assert!(too_few.contains("has 19"), "{too_few}");
    assert!(enforceable(&confirmed(2, ENFORCE_AFTER)).is_ok());
    let failing = enforceable(&confirmed(3, ENFORCE_AFTER)).expect_err("3 of 20");
    assert!(failing.contains("failed 3 of 20"), "{failing}");

    let mut with_others = confirmed(2, ENFORCE_AFTER);
    with_others.extend((0..10).map(|_| labelled(0.1, "fail", false)));
    with_others.extend((0..10).map(|_| labelled(0.5, "skipped", true)));
    assert_eq!(failing_confirmed(&with_others), (2, ENFORCE_AFTER));
    assert!(enforceable(&with_others).is_ok());
}
