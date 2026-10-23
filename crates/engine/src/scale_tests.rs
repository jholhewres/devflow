use super::*;
use crate::config::{Agent, Config};

/// A diff that adds `lines` lines to `file`.
fn added(file: &str, lines: usize) -> String {
    format!(
        "diff --git a/{file} b/{file}\n--- a/{file}\n+++ b/{file}\n@@ -0,0 +1,{lines} @@\n{}",
        "+a line\n".repeat(lines)
    )
}

fn sized_of(files: &[&str], diff: &str) -> Sized {
    let files: Vec<String> = files.iter().map(|one| (*one).to_owned()).collect();
    sized(&Scale::default(), &files, diff)
}

#[test]
fn a_small_diff_of_docs_and_tests_is_read_by_one_reviewer() {
    let diff = added("docs/guide.md", 10) + &added("tests/a_link_opens.rs", 20);
    let said = sized_of(&["docs/guide.md", "tests/a_link_opens.rs"], &diff);
    assert!(said.one, "{}", said.why);
    assert_eq!(
        said.why,
        "scaled: small diff (30 changed lines), no sensitive path → one reviewer (devflow-all)"
    );
}

#[test]
fn a_diff_touching_a_migration_gets_the_configured_reviewers() {
    let file = "db/migrations/0003_add_owner.rb";
    let said = sized_of(&["docs/guide.md", file], &added(file, 3));
    assert!(!said.one);
    assert!(
        said.why.starts_with(
            "not scaled: db/migrations/0003_add_owner.rb is a sensitive path (*migration*)"
        ),
        "{}",
        said.why
    );
}

#[test]
fn a_diff_past_the_size_gets_the_configured_reviewers() {
    let at_most = SMALL_LINES as usize;
    assert!(sized_of(&["docs/guide.md"], &added("docs/guide.md", at_most)).one);
    let said = sized_of(&["docs/guide.md"], &added("docs/guide.md", at_most + 1));
    assert!(!said.one);
    assert!(
        said.why.contains("81 changed lines, past 80"),
        "{}",
        said.why
    );
}

#[test]
fn the_lines_are_counted_through_each_hunk() {
    // A removed SQL comment reads like a `---` header; it is still a line.
    let diff = "--- a/q.txt\n+++ b/q.txt\n@@ -1,3 +1,2 @@\n kept\n--- old note\n-gone\n+new\n";
    assert_eq!(changed_lines(diff), Some(3));
    assert_eq!(
        changed_lines(
            "diff --git a/logo.png b/logo.png\nBinary files a/logo.png and b/logo.png differ\n"
        ),
        None
    );
}

#[test]
fn a_pattern_without_a_slash_matches_any_part_of_the_path() {
    for (pattern, path) in [
        ("*auth*", "src/OAuth/mod.rs"),
        ("*.lock", "Cargo.lock"),
        (".env*", "deploy/.env.production"),
        (".github/workflows/**", ".github/workflows/ci.yml"),
        ("requirements*.txt", "requirements-dev.txt"),
    ] {
        assert!(matches(pattern, path), "{pattern} {path}");
    }
    for (pattern, path) in [
        ("*.sql", "docs/sql.md"),
        (".github/workflows/**", "docs/.github/workflows/ci.yml"),
        ("Cargo.toml", "docs/cargo.toml.md"),
    ] {
        assert!(!matches(pattern, path), "{pattern} {path}");
    }
}

#[test]
fn scaled_the_first_reviewers_cli_reads_every_axis_and_unscaled_nothing_changes() {
    let mut config = Config::default();
    config.review.reviewers = vec![
        Reviewer {
            agent: Agent::Codex,
            persona: "devflow-spec".into(),
            model: Some("o3".into()),
        },
        Reviewer {
            agent: Agent::Claude,
            persona: "devflow-security".into(),
            model: None,
        },
    ];
    let one = reviewers(&config.review, true);
    assert_eq!(
        one,
        [Reviewer {
            agent: Agent::Codex,
            persona: ALL_AXES.into(),
            model: Some("o3".into()),
        }]
    );
    assert_eq!(reviewers(&config.review, false), config.review.reviewers);
    assert!(reviewers(&Config::default().review, true).is_empty());
}
