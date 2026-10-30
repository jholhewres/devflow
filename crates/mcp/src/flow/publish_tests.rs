use devflow_engine::publish::{Inline, Posted};
use serde_json::json;

use super::{ids_of, posted_from};

/// #248: the comments as GitHub lists them for the pull request — a line,
/// or only an original line once outdated — matched to the review that
/// posted them, never to another review's comment on the same line.
#[test]
fn the_comments_a_review_posted_are_found_by_the_line_github_lists_them_on() {
    let wanted = [
        Inline {
            file: "app/RateLimitingServiceProvider.php".to_owned(),
            line: 106,
            body: "a".to_owned(),
        },
        Inline {
            file: "app/Old.php".to_owned(),
            line: 12,
            body: "b".to_owned(),
        },
        Inline {
            file: "app/Gone.php".to_owned(),
            line: 3,
            body: "c".to_owned(),
        },
    ];
    let listed = json!([
        { "id": 1, "pull_request_review_id": 7, "path": "app/RateLimitingServiceProvider.php", "line": 106, "original_line": 106 },
        { "id": 2, "pull_request_review_id": 8, "path": "app/RateLimitingServiceProvider.php", "line": 106, "original_line": 106 },
        { "id": 3, "pull_request_review_id": 8, "path": "app/Old.php", "line": null, "original_line": 12 },
        { "id": 4, "pull_request_review_id": 8, "path": "app/Gone.php", "line": 9, "original_line": 3 },
    ]);
    let listed = listed.as_array().expect("a list");
    assert_eq!(ids_of(&wanted, listed, 8), [Some(2), Some(3), Some(4)]);
}

/// #248: GitHub took the review but its comments could not be read back:
/// the review is still kept as posted, so a retry does not post it again.
#[test]
fn a_review_posted_whose_comments_cannot_be_read_back_is_kept_as_posted() {
    let wanted = [Inline {
        file: "app/A.php".to_owned(),
        line: 1,
        body: "a".to_owned(),
    }];
    let posted = posted_from(8, &wanted, Err("gh api timed out".to_owned()));
    assert_eq!(
        posted,
        Posted {
            review: 8,
            ids: vec![None]
        }
    );
}

/// A comment posted at 3 that the pull request now shows at 9 never takes
/// the id of the one posted at 9: a later edit would change the wrong one.
#[test]
fn a_comment_that_moved_onto_anothers_line_keeps_its_own_id() {
    let at = |line: u64| Inline {
        file: "app/A.php".to_owned(),
        line,
        body: String::new(),
    };
    let listed = json!([
        { "id": 30, "pull_request_review_id": 8, "path": "app/A.php", "line": 9, "original_line": 3 },
        { "id": 90, "pull_request_review_id": 8, "path": "app/A.php", "line": 15, "original_line": 9 },
    ]);
    let listed = listed.as_array().expect("a list");
    assert_eq!(ids_of(&[at(9), at(3)], listed, 8), [Some(90), Some(30)]);
}
