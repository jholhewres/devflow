use serde_json::json;

use super::*;

#[test]
fn a_review_without_a_card_names_a_pr_a_range_or_a_worktree() {
    let read = |params: Value| standalone(&params).expect("read").expect("no card");
    assert_eq!(read(json!({ "pr": 42 })).subject, Subject::Pr(42));
    assert_eq!(
        read(json!({ "pr": "https://github.com/acme/app/pull/7/" })).subject,
        Subject::Pr(7)
    );
    assert_eq!(
        read(json!({ "base": "main", "head": "feature" })).subject,
        Subject::Range {
            base: "main".into(),
            head: "feature".into()
        }
    );
    assert_eq!(
        read(json!({ "path": "/w/one" })).subject,
        Subject::Path {
            path: "/w/one".into(),
            base: None
        }
    );
    let handed = read(json!({ "pr": 3, "run": "20261011T143005Z", "reports": [{}] }));
    assert_eq!(handed.run.as_deref(), Some("20261011T143005Z"));
}

#[test]
fn a_card_call_is_left_to_the_cards_review_and_refuses_what_is_not_its() {
    assert_eq!(standalone(&json!({ "card": "card_1" })), Ok(None));
    let refused = review::asked(&json!({ "card": "card_1", "pr": 4 })).expect_err("refused");
    assert!(refused.contains("leave out `card`"), "{refused}");
}

#[test]
fn what_reaches_git_is_never_an_option_and_the_subject_is_one() {
    for params in [
        json!({}),
        json!({ "head": "feature" }),
        json!({ "base": "main" }),
        json!({ "base": "--output=/tmp/x", "head": "feature" }),
        json!({ "base": "main", "head": "-x" }),
        json!({ "pr": 4, "base": "main" }),
        json!({ "pr": "../evil" }),
        json!({ "pr": 0 }),
        json!({ "path": "/w", "head": "x" }),
        json!({ "pr": 4, "previous": "20261011T143005Z" }),
        json!({ "pr": 4, "run": "20261011T143005Z" }),
        json!({ "pr": 4, "criteria": "one" }),
    ] {
        assert!(standalone(&params).is_err(), "{params}");
    }
}

#[test]
fn a_pull_request_is_held_to_its_checkboxes_else_its_title_and_body() {
    let boxed = "Why\n## Acceptance criteria\n- [ ] it opens\n";
    assert_eq!(
        pr_criteria(&["given".into()], "T", boxed),
        ["given", "it opens"]
    );
    assert_eq!(
        pr_criteria(&[], "Fix the links", "They\nopened twice."),
        ["Fix the links", "They opened twice."]
    );
    let body = body_of(&pr_criteria(&[], "Fix", ""));
    let read: Vec<String> = crate::criteria::criteria(&body)
        .into_iter()
        .map(|one| one.text)
        .collect();
    assert_eq!(read, ["Fix"]);
}

#[test]
fn a_reviews_runs_are_kept_under_its_pr_or_its_commits() {
    let (base, head) = ("a".repeat(40), "b".repeat(40));
    assert_eq!(label(&Subject::Pr(42), &base, &head), "pr-42");
    let range = Subject::Range {
        base: "main".into(),
        head: "x".into(),
    };
    let named = label(&range, &base, &head);
    assert_eq!(named, format!("{}-{}", &base[..12], &head[..12]));
    assert!(crate::runs::plain_card(&named));
}

#[test]
fn a_retro_review_reads_a_merged_range_and_nothing_else() {
    let read = |params: Value| standalone(&params).map(|asked| asked.map(|one| one.retro));
    assert_eq!(
        read(json!({ "base": "v1", "head": "v2", "mode": "retro" })),
        Ok(Some(true))
    );
    assert_eq!(read(json!({ "base": "v1", "head": "v2" })), Ok(Some(false)));
    for params in [
        json!({ "pr": 4, "mode": "retro" }),
        json!({ "path": "/w", "mode": "retro" }),
        json!({ "base": "v1", "head": "v2", "mode": "strict" }),
    ] {
        assert!(read(params.clone()).is_err(), "{params}");
    }
    let refused =
        review::asked(&json!({ "card": "card_1", "mode": "retro" })).expect_err("refused");
    assert!(refused.contains("leave out `card`"), "{refused}");
    let range = Subject::Range {
        base: "v1".into(),
        head: "v2".into(),
    };
    let done = next(&range, "aaa-bbb", "20261014T120000Z", &[], None, true);
    assert!(
        done.contains("`impact` read-only") && done.contains("ticket"),
        "{done}"
    );
}
