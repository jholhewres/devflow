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
