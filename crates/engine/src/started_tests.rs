use super::*;

const CARD: &str = "card_01ABCDEF";

fn runs_in(dir: &std::path::Path) -> Runs {
    Runs {
        home: dir.join("home"),
        checkout: dir.to_path_buf(),
    }
}

#[test]
fn the_first_start_is_kept_and_a_later_one_does_not_move_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let runs = runs_in(dir.path());
    assert_eq!(start_of(&runs, CARD), None);
    keep_start(&runs, CARD, "abc123").expect("kept");
    keep_start(&runs, CARD, "def456").expect("again");
    assert_eq!(start_of(&runs, CARD).as_deref(), Some("abc123"));
}

#[test]
fn a_start_that_is_not_a_commit_is_not_taken() {
    let dir = tempfile::tempdir().expect("tempdir");
    let runs = runs_in(dir.path());
    keep_start(&runs, CARD, "main; rm -rf /").expect("kept");
    assert_eq!(start_of(&runs, CARD), None);
}

#[test]
fn a_start_an_older_devpit_kept_in_the_checkout_stays_the_cards() {
    let dir = tempfile::tempdir().expect("tempdir");
    let runs = runs_in(dir.path());
    let older = dir.path().join(crate::runs::RUNS).join(CARD);
    std::fs::create_dir_all(&older).expect("older");
    std::fs::write(older.join(STARTED), r#"{ "head": "abc123" }"#).expect("start");
    keep_start(&runs, CARD, "def456").expect("again");
    assert_eq!(start_of(&runs, CARD).as_deref(), Some("abc123"));
}
