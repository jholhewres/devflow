use super::*;

#[test]
fn exit_zero_without_a_report_is_never_a_pass() {
    assert_eq!(verdict(RunState::Ok, None), Verdict::Inconclusive);
    let none_ran = Report {
        passed: 0,
        failed: 0,
    };
    assert_eq!(verdict(RunState::Ok, Some(none_ran)), Verdict::Inconclusive);
}

#[test]
fn a_report_decides_once_the_process_ended() {
    let green = Report {
        passed: 3,
        failed: 0,
    };
    let red = Report {
        passed: 3,
        failed: 1,
    };
    assert_eq!(verdict(RunState::Ok, Some(green)), Verdict::Passed);
    assert_eq!(verdict(RunState::Ok, Some(red)), Verdict::Failed);
    assert_eq!(verdict(RunState::Failed, Some(red)), Verdict::Failed);
    assert_eq!(
        verdict(RunState::Failed, Some(green)),
        Verdict::Inconclusive
    );
    assert_eq!(verdict(RunState::Lost, Some(green)), Verdict::Inconclusive);
    assert_eq!(verdict(RunState::Cancelled, Some(green)), Verdict::NotRun);
}

#[test]
fn added_reports_keep_a_bounded_list_of_failures_and_an_exact_count() {
    let failing = |count: usize| Tested {
        failed: count as u32,
        failures: (0..count)
            .map(|at| FailedTest {
                name: format!("t{at}"),
                file: None,
                message: None,
            })
            .collect(),
        read_from: vec!["JUnit".to_owned()],
        ..Tested::default()
    };
    let mut total = failing(40);
    total.add(failing(40));
    assert_eq!(total.failed, 80);
    assert_eq!(total.failures.len(), MOST_FAILURES_KEPT);
    assert_eq!(total.read_from, ["JUnit"]);
}
