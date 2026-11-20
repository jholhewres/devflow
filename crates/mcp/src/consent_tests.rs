use super::*;

#[test]
fn what_the_person_switched_on_is_kept_per_project() {
    let folder = tempfile::tempdir().expect("folder");
    let one = tempfile::tempdir().expect("one");
    let other = tempfile::tempdir().expect("other");
    let consent = Consent::at(folder.path());
    assert!(!consent.made(one.path(), Ask::Enable));
    consent
        .remember(one.path(), Ask::Enable, true)
        .expect("kept");
    assert!(consent.made(one.path(), Ask::Enable));
    assert!(!consent.made(one.path(), Ask::Enforce));
    assert!(!consent.made(other.path(), Ask::Enable));
    consent
        .remember(one.path(), Ask::Enable, false)
        .expect("forgot");
    assert!(!consent.made(one.path(), Ask::Enable));
}

#[test]
fn a_confirmed_command_is_known_by_its_fingerprint() {
    let folder = tempfile::tempdir().expect("folder");
    let consent = Consent::at(folder.path());
    assert!(!consent.command_confirmed("sha256:a"));
    consent.confirm("sha256:a").expect("confirmed");
    consent.confirm("sha256:a").expect("again");
    assert!(consent.command_confirmed("sha256:a"));
    assert_eq!(consent.kept().commands.len(), 1);
}

#[test]
fn the_targets_confirmed_are_kept_by_project_and_narrowed_by_a_shorter_list() {
    let (folder, one, other) = (
        tempfile::tempdir().expect("folder"),
        tempfile::tempdir().expect("one"),
        tempfile::tempdir().expect("other"),
    );
    let consent = Consent::at(folder.path());
    assert!(consent.confirmed_targets(one.path()).is_empty());
    let both = [
        "http://localhost:8080".to_owned(),
        "http://api:8000".to_owned(),
    ];
    consent
        .confirm_targets(one.path(), &both, &Pins::new())
        .expect("both");
    assert_eq!(consent.confirmed_targets(one.path()), both);
    assert!(consent.confirmed_targets(other.path()).is_empty());
    consent
        .confirm_targets(one.path(), &both[..1], &Pins::new())
        .expect("narrowed");
    assert_eq!(consent.confirmed_targets(one.path()), both[..1]);
    consent
        .confirm_targets(one.path(), &[], &Pins::new())
        .expect("none");
    assert!(consent.kept().targets.is_empty());
}

#[test]
fn the_addresses_a_name_resolved_to_are_kept_with_the_yes() {
    let (folder, one) = (
        tempfile::tempdir().expect("folder"),
        tempfile::tempdir().expect("one"),
    );
    let consent = Consent::at(folder.path());
    let both = [
        "http://localhost:8080".to_owned(),
        "http://api:8000".to_owned(),
    ];
    let pins = Pins::from([
        (
            "http://api:8000".to_owned(),
            vec!["172.18.0.3".parse().expect("ip")],
        ),
        (
            "http://localhost:8080".to_owned(),
            vec!["127.0.0.1".parse().expect("ip")],
        ),
    ]);
    consent
        .confirm_targets(one.path(), &both, &pins)
        .expect("both");
    assert_eq!(consent.pinned(one.path()), pins);
    consent
        .confirm_targets(one.path(), &both[..1], &pins)
        .expect("narrowed");
    let left: Vec<String> = consent.pinned(one.path()).into_keys().collect();
    assert_eq!(left, ["http://localhost:8080"]);
}

#[test]
fn a_record_from_before_the_addresses_were_kept_still_reads() {
    let (folder, one) = (
        tempfile::tempdir().expect("folder"),
        tempfile::tempdir().expect("one"),
    );
    let key = key_of(one.path());
    let old =
        serde_json::json!({ "enabled": [key], "targets": { key.clone(): ["http://api:8000"] } });
    std::fs::write(folder.path().join(FILE), old.to_string()).expect("old");
    let consent = Consent::at(folder.path());
    assert!(consent.made(one.path(), Ask::Enable));
    assert_eq!(consent.confirmed_targets(one.path()), ["http://api:8000"]);
    assert!(consent.pinned(one.path()).is_empty());
}

#[test]
fn a_stack_is_in_force_only_while_its_compose_file_is_what_was_confirmed() {
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().join("project");
    std::fs::create_dir_all(&root).expect("project");
    std::fs::write(root.join("compose.yaml"), "services: {}\n").expect("compose");
    let consent = Consent::at(&dir.path().join("home"));
    assert_eq!(
        consent.stack_in_force(&root, Some("compose.yaml")),
        None,
        "never confirmed"
    );
    consent
        .confirm_stack(&root, Some("compose.yaml"))
        .expect("confirmed");
    assert_eq!(
        consent
            .stack_in_force(&root, Some("compose.yaml"))
            .as_deref(),
        Some("compose.yaml")
    );
    assert_eq!(
        consent.stack_in_force(&root, Some("other.yaml")),
        None,
        "another file"
    );
    std::fs::write(
        root.join("compose.yaml"),
        "services: { web: { image: x } }\n",
    )
    .expect("changed");
    assert_eq!(
        consent.stack_in_force(&root, Some("compose.yaml")),
        None,
        "changed since"
    );
}
