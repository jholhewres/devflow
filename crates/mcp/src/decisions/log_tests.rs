use super::*;

fn row(project: &str, cost: f64, at: i64, failure: Option<&str>) -> Row {
    Row {
        at,
        project: Some(project.to_owned()),
        item: Some("3".to_owned()),
        gate: "devflow-done".to_owned(),
        mode: "shadow".to_owned(),
        rubric: Some("devflow-done".to_owned()),
        questions: "{}".to_owned(),
        outcome: if failure.is_some() { "skipped" } else { "pass" }.to_owned(),
        cost_usd: cost,
        state_digest: "abc:3".to_owned(),
        failure: failure.map(str::to_owned),
        ..Row::default()
    }
}

#[test]
fn decisions_are_kept_newest_first_with_their_labels() {
    let folder = tempfile::tempdir().unwrap();
    let log = Log::at(&folder.path().join(FILE));
    assert!(log.rows().is_empty());
    assert!(
        log.spend_since(0).is_sign_positive(),
        "nothing spent is 0, not -0"
    );
    let first = log.write(row("/a", 0.25, 100, None)).unwrap();
    log.write(row("/a", 0.5, 200, Some("unreachable"))).unwrap();
    log.write(row("/b", 1.0, 50, None)).unwrap();
    log.label(&first, true, "finished").unwrap();
    let rows = log.rows();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[2].person_verdict.as_deref(), Some("pass"));
    assert_eq!(log.spend_since(100), 0.75);
    assert_eq!(log.failed_last("/a").as_deref(), Some("unreachable"));
    assert_eq!(log.failed_last("/b"), None);
    assert_eq!(log.of_item("3", "devflow-done").len(), 3);
}
