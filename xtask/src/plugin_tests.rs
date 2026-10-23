use super::*;

#[test]
fn a_written_plugin_has_no_drift_and_an_extra_file_is_named() {
    let root = tempfile::tempdir().unwrap();
    let files = vec![
        ("skills/plan/SKILL.md".to_owned(), "plan\n".to_owned()),
        ("hooks/hooks.json".to_owned(), "{}\n".to_owned()),
    ];
    assert_eq!(drift(root.path(), &files).len(), 2);
    assert_eq!(write(root.path(), &files).unwrap(), 2);
    assert!(drift(root.path(), &files).is_empty());
    std::fs::write(root.path().join("skills/old.md"), "old").unwrap();
    assert_eq!(
        drift(root.path(), &files),
        ["skills/old.md is not a file of the plugin"]
    );
    write(root.path(), &files).unwrap();
    assert!(!root.path().join("skills/old.md").exists());
}
