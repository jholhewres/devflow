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
fn a_confirmed_stack_is_kept_with_the_digest_compose_resolved_then() {
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().join("project");
    std::fs::create_dir_all(&root).expect("project");
    let consent = Consent::at(&dir.path().join("home"));
    assert_eq!(consent.confirmed_stack(&root), None, "never confirmed");
    consent
        .confirm_stack(&root, Some(("compose.yaml", "abc123")))
        .expect("confirmed");
    assert_eq!(
        consent.confirmed_stack(&root),
        Some(("compose.yaml".to_owned(), "abc123".to_owned()))
    );
    consent.confirm_stack(&root, None).expect("forgotten");
    assert_eq!(consent.confirmed_stack(&root), None);
}

#[test]
fn how_when_and_what_for_the_person_said_yes_is_kept_by_project() {
    use std::time::{Duration, SystemTime};
    let (folder, one, other) = (
        tempfile::tempdir().expect("folder"),
        tempfile::tempdir().expect("one"),
        tempfile::tempdir().expect("other"),
    );
    let consent = Consent::at(folder.path());
    let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_795_000_000);
    consent
        .record(one.path(), "enabled", How::Elicitation, "attack", at)
        .expect("kept");
    consent
        .record(
            one.path(),
            "security.targets",
            How::Terminal,
            "config set",
            at,
        )
        .expect("kept");
    let given = consent.given(one.path());
    assert_eq!(given.len(), 2);
    assert_eq!(given[0].what, "enabled");
    assert_eq!(given[0].how, How::Elicitation);
    assert_eq!(given[0].asked_for, "attack");
    assert_eq!(given[0].at, "20261118T110640Z");
    assert_eq!(given[1].how, How::Terminal);
    assert!(consent.given(other.path()).is_empty(), "by project");
    let file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(folder.path().join(FILE)).expect("file"))
            .expect("json");
    let said = file["given"].to_string();
    assert!(said.contains("\"how\":\"elicitation\""), "{said}");
    assert!(said.contains("\"for\":\"attack\""), "{said}");
    for _ in 0..MOST_GIVEN + 5 {
        consent
            .record(one.path(), "enabled", How::Terminal, "setup", at)
            .expect("kept");
    }
    assert_eq!(
        consent.kept().given.len(),
        MOST_GIVEN,
        "the newest are kept"
    );

    assert!(consent.answered(one.path()).is_empty());
    let answered = |parts: &[&str]| {
        let parts: Vec<String> = parts.iter().map(|one| one.to_string()).collect();
        consent
            .keep_answer(
                one.path(),
                &Answered {
                    switched_on: false,
                    targets: None,
                    yeses: &[],
                    parts: &parts,
                    how: How::Elicitation,
                    asked_for: "attack",
                    at,
                },
            )
            .expect("kept");
    };
    answered(&["test", "run_usd"]);
    answered(&["test"]);
    let parts: Vec<String> = consent.answered(one.path()).into_iter().collect();
    assert_eq!(parts, ["run_usd", "test"]);
    assert!(consent.answered(other.path()).is_empty());
    assert!(
        !consent.made(one.path(), Ask::Enable),
        "a part is not a switch"
    );
    // Past the most kept, the oldest part goes first.
    for index in 0..MOST_COMMANDS {
        answered(&[&format!("targets:{index}")]);
    }
    let kept = consent.answered(one.path());
    assert!(
        !kept.contains("run_usd") && !kept.contains("test"),
        "{kept:?}"
    );
    assert!(kept.contains("targets:0"));
}

/// A repository with one commit, and a linked worktree of it: both roots.
fn worktree_of_a_repository(dir: &Path) -> (PathBuf, PathBuf) {
    let git = |at: &Path, args: &[&str]| {
        let done = std::process::Command::new("git")
            .args(args)
            .current_dir(at)
            .output()
            .unwrap();
        assert!(done.status.success(), "git {args:?}");
    };
    let main = dir.join("main");
    std::fs::create_dir_all(&main).unwrap();
    git(&main, &["init", "-q"]);
    git(&main, &["config", "user.email", "test@example.invalid"]);
    git(&main, &["config", "user.name", "Test"]);
    git(&main, &["config", "commit.gpgsign", "false"]);
    std::fs::write(main.join("a.txt"), "a\n").unwrap();
    git(&main, &["add", "-A"]);
    git(&main, &["commit", "-q", "-m", "first"]);
    let worktree = dir.join("wt");
    git(
        &main,
        &[
            "worktree",
            "add",
            "-q",
            worktree.to_str().unwrap(),
            "-b",
            "wt",
        ],
    );
    (
        main.canonicalize().unwrap(),
        worktree.canonicalize().unwrap(),
    )
}

/// A linked worktree with no decision of its own takes its main
/// checkout's: the switch, said to come from there, and the parts already
/// answered. Its own no stands over the main checkout's yes, and its own
/// yes over the main checkout's no.
#[test]
fn a_worktree_takes_its_main_checkouts_decisions_unless_it_has_its_own() {
    let dir = tempfile::tempdir().unwrap();
    let (main, worktree) = worktree_of_a_repository(dir.path());
    let consent = Consent::at(&dir.path().join("config"));
    assert!(!consent.made(&worktree, Ask::Enable));
    consent.remember(&main, Ask::Enable, true).unwrap();
    assert!(consent.made(&worktree, Ask::Enable));
    assert_eq!(
        consent.made_where(&worktree, Ask::Enable),
        Some(Made::Main(main.clone()))
    );
    assert_eq!(consent.made_where(&main, Ask::Enable), Some(Made::Here));
    assert!(!consent.made(&worktree, Ask::Enforce), "only what was made");
    consent
        .keep_answer(
            &main,
            &Answered {
                switched_on: true,
                targets: None,
                yeses: &["enabled"],
                parts: &["test".to_owned()],
                how: How::Terminal,
                asked_for: "attack",
                at: std::time::SystemTime::now(),
            },
        )
        .unwrap();
    assert!(consent.answered(&worktree).contains("test"));
    assert_eq!(consent.given(&worktree).len(), 1);

    consent.remember(&worktree, Ask::Enable, false).unwrap();
    assert!(!consent.made(&worktree, Ask::Enable), "its own no stands");
    assert!(consent.made(&main, Ask::Enable));
    consent.remember(&worktree, Ask::Enable, true).unwrap();
    consent.remember(&main, Ask::Enable, false).unwrap();
    assert_eq!(consent.made_where(&worktree, Ask::Enable), Some(Made::Here));
}
