use super::*;

#[test]
fn a_change_is_said_line_by_line_and_file_by_file() {
    let before = ["version: 2".to_owned(), "block_on: [critical]".to_owned()];
    let after = [
        "version: 2".to_owned(),
        "block_on: [critical, high]".to_owned(),
    ];
    assert_eq!(
        lines_changed(&before, &after),
        ["- block_on: [critical]", "+ block_on: [critical, high]"]
    );
    assert!(lines_changed(&before, &before).is_empty());
}

#[test]
fn approving_a_commit_this_machine_never_fetched_is_refused() {
    let base = tempfile::tempdir().expect("tempdir");
    let home = Home::under(base.path());
    let layer = Extend {
        git: "/nowhere/acme.git".into(),
        reference: "v1".into(),
    };
    let refused = approve(base.path(), &layer, "0123456789abcdef", &home).expect_err("refused");
    assert!(refused.contains("not on this machine"), "{refused}");
    assert!(!base.path().join(crate::layers::LOCK).exists());
}
