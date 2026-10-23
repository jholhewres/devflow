use super::*;

fn brief() -> Brief {
    Brief {
        title: Some("Search by body".into()),
        goal: Some("Find a card by what its body says".into()),
        for_whom: Some("people with long boards".into()),
        success: Some("`make test` passes with the new search tests".into()),
        out_of_scope: Some(vec!["comments".into(), "fuzzy matching".into()]),
        constraints: Some(Vec::new()),
        decisions: Some(vec!["one index for titles and bodies".into()]),
        context: None,
    }
}

#[test]
fn an_epic_is_titled_once_whatever_it_was_given() {
    assert_eq!(
        epic_title("Search by body"),
        "[devflow] Brief: Search by body"
    );
    assert_eq!(
        epic_title("[devflow] Brief:  Search   by body"),
        "[devflow] Brief: Search by body"
    );
}

#[test]
fn a_brief_reads_as_markdown_and_names_what_is_left_out() {
    let body = written("", &brief());
    assert_eq!(
        body,
        "## Brief\n\
         - Goal: Find a card by what its body says\n\
         - For whom: people with long boards\n\
         - Success: `make test` passes with the new search tests\n\
         \n\
         ### Out of scope\n\
         - comments\n\
         - fuzzy matching\n\
         \n\
         ### Constraints\n\
         - none\n\
         \n\
         ### Decisions\n\
         - one index for titles and bodies"
    );
}

#[test]
fn a_later_write_changes_only_what_it_was_given() {
    let request = "The person asked: search should look inside cards.";
    let first = written(request, &brief());
    assert!(
        first.starts_with(&format!("{request}\n\n## Brief\n")),
        "{first}"
    );

    let context = "## Context\n### Facts\n- titles are indexed (`crates/core/src/store/search_index.rs:12`)\n### Not confirmed\n- none";
    let with_context = written(
        &first,
        &Brief {
            context: Some(context.into()),
            ..Brief::default()
        },
    );
    assert!(
        with_context.ends_with(&format!("- one index for titles and bodies\n\n{context}")),
        "{with_context}"
    );

    let corrected = written(
        &with_context,
        &Brief {
            goal: Some("Find a card by its body or its title".into()),
            ..Brief::default()
        },
    );
    assert!(
        corrected.contains(
            "- Goal: Find a card by its body or its title\n- For whom: people with long boards"
        ),
        "{corrected}"
    );
    assert!(
        corrected.contains("- one index for titles and bodies"),
        "{corrected}"
    );
    assert!(
        corrected.starts_with(request) && corrected.ends_with(context),
        "{corrected}"
    );

    // The context again replaces the context, and only it.
    let again = written(
        &corrected,
        &Brief {
            context: Some("### Facts\n- none".into()),
            ..Brief::default()
        },
    );
    assert!(
        again.contains("## Context\n### Facts\n- none") && !again.contains("search_index.rs:12"),
        "{again}"
    );
    assert!(
        again.contains("- Goal: Find a card by its body or its title"),
        "{again}"
    );
}
