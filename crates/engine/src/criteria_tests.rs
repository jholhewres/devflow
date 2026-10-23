use super::*;

const BODY: &str = "\
Search finds a card by its body.

- [ ] not a criterion: above the heading

## Acceptance criteria
- [ ] typing a word lists the cards that hold it
* [x] an empty query lists nothing
  - [X] indented, still one

### Notes inside the section
- [ ] still a criterion

```sh
- [ ] code, not a criterion
```

## Verify
- [ ] after the section: not a criterion
";

fn said(body: &str) -> Vec<(String, bool)> {
    criteria(body)
        .into_iter()
        .map(|one| (one.text, one.done))
        .collect()
}

#[test]
fn the_criteria_are_the_checkboxes_under_their_heading() {
    assert_eq!(
        said(BODY),
        [
            (
                "typing a word lists the cards that hold it".to_owned(),
                false
            ),
            ("an empty query lists nothing".to_owned(), true),
            ("indented, still one".to_owned(), true),
            ("still a criterion".to_owned(), false),
        ]
    );
    assert!(criteria("no heading\n- [ ] a box").is_empty());
    assert_eq!(said("### acceptance criteria:\n- [ ] any case\n").len(), 1);
}

#[test]
fn a_tick_writes_the_box_and_nothing_else() {
    let first = ticked(BODY, 0, true).expect("a first criterion");
    assert_eq!(
        said(&first)[0],
        (
            "typing a word lists the cards that hold it".to_owned(),
            true
        )
    );
    let untouched: Vec<&str> = BODY
        .lines()
        .filter(|line| !line.contains("typing a word"))
        .collect();
    let after: Vec<&str> = first
        .lines()
        .filter(|line| !line.contains("typing a word"))
        .collect();
    assert_eq!(untouched, after);

    let unticked = ticked(BODY, 2, false).expect("a third criterion");
    assert!(
        unticked.contains("  - [ ] indented, still one"),
        "{unticked}"
    );
    assert!(ticked(BODY, 4, true).is_none());
}

#[test]
fn a_line_ending_in_a_return_keeps_it() {
    let body = "## Acceptance criteria\r\n- [ ] one\r\n";
    assert_eq!(
        ticked(body, 0, true).as_deref(),
        Some("## Acceptance criteria\r\n- [x] one\r\n")
    );
}
