use std::time::{Duration, UNIX_EPOCH};

use super::*;

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_791_729_005 + seconds)
}

fn new(title: &str) -> New {
    New {
        title: title.to_owned(),
        kind: Kind::Item,
        parent: None,
        depends_on: Vec::new(),
        body: "## Acceptance criteria\n- [ ] it renames\n".to_owned(),
    }
}

#[test]
fn an_item_is_a_file_a_person_can_read_and_it_reads_back_the_same() {
    let root = tempfile::tempdir().expect("root");
    let items = Files::of(root.path());
    let epic = items
        .create(
            &New {
                kind: Kind::Epic,
                ..new("[devflow] Brief: rename")
            },
            at(0),
        )
        .expect("epic");
    let slice = items
        .create(
            &New {
                parent: Some(epic.id.clone()),
                depends_on: vec![epic.id.clone()],
                ..new("Rename a card")
            },
            at(1),
        )
        .expect("slice");
    assert_eq!((epic.id.as_str(), slice.id.as_str()), ("1", "2"));

    let text = std::fs::read_to_string(root.path().join(".devflow/work/2.md")).expect("file");
    assert!(text.starts_with("---\nid: \"2\"\ntitle: \"Rename a card\"\nkind: item\nstate: open\nparent: \"1\"\ndepends_on: [\"1\"]\n"), "{text}");
    assert!(
        text.contains("---\n## Acceptance criteria\n- [ ] it renames\n"),
        "{text}"
    );
    assert_eq!(items.get("2").expect("read"), Some(slice));
    assert_eq!(
        items
            .list()
            .expect("list")
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        ["1", "2"]
    );
}

#[test]
fn comments_follow_the_body_and_an_edit_of_the_body_keeps_them() {
    let root = tempfile::tempdir().expect("root");
    let items = Files::of(root.path());
    let item = items.create(&new("Rename"), at(0)).expect("item");
    items
        .comment(
            &item.id,
            "agent",
            "Started.\n\n### not a heading of ours",
            at(1),
        )
        .expect("comment");
    items
        .comment(&item.id, "devflow", "Gate: passed.", at(2))
        .expect("comment");
    let ticked = crate::criteria::ticked(&item.body, 0, true).expect("ticked");
    items.update_body(&item.id, &ticked).expect("body");
    items.set_state(&item.id, State::Done).expect("state");

    let read = items.get(&item.id).expect("read").expect("there");
    assert_eq!(read.state, State::Done);
    assert!(crate::criteria::criteria(&read.body)[0].done);
    let comments = items.comments(&item.id).expect("comments");
    assert_eq!(comments.len(), 2);
    assert_eq!(comments[0].by, "agent");
    assert_eq!(comments[0].text, "Started.\n\n### not a heading of ours");
    assert_eq!(comments[1].text, "Gate: passed.");
}

#[test]
fn what_the_folder_cannot_hold_is_refused() {
    let root = tempfile::tempdir().expect("root");
    let items = Files::of(root.path());
    assert!(items.create(&new(""), at(0)).is_err(), "no title");
    let waits = New {
        depends_on: vec!["9".to_owned()],
        ..new("Waits")
    };
    assert!(
        items.create(&waits, at(0)).is_err(),
        "an item that is not there"
    );
    assert!(items.get("../secret").is_err());
    assert_eq!(items.get("7").expect("read"), None);
    assert!(items.set_state("7", State::Done).is_err());
    let item = items.create(&new("Rename"), at(0)).expect("item");
    assert!(items
        .update_body(&item.id, &format!("x\n{COMMENTS}\n"))
        .is_err());
    assert!(items.comment(&item.id, "agent", "  ", at(1)).is_err());
}

#[cfg(unix)]
#[test]
fn a_link_in_the_folder_is_not_an_item() {
    let root = tempfile::tempdir().expect("root");
    let elsewhere = tempfile::tempdir().expect("elsewhere");
    std::fs::write(elsewhere.path().join("1.md"), "---\ntitle: x\n---\n").expect("write");
    std::fs::create_dir_all(root.path().join(".devflow/work")).expect("folder");
    std::os::unix::fs::symlink(
        elsewhere.path().join("1.md"),
        root.path().join(".devflow/work/1.md"),
    )
    .expect("link");
    let items = Files::of(root.path());
    assert!(items.list().expect("list").is_empty());
    assert!(items.get("1").is_err());
}

#[test]
fn a_project_on_devpits_folder_keeps_its_items_there() {
    let root = tempfile::tempdir().expect("root");
    std::fs::create_dir_all(root.path().join(".devpit/devflow")).expect("folder");
    std::fs::write(root.path().join(crate::locate::DEVPIT), "version: 2\n").expect("yaml");
    let items = Files::of(root.path());
    assert_eq!(items.relative(), ".devpit/devflow/work");
    items.create(&new("Rename"), at(0)).expect("item");
    assert!(root.path().join(".devpit/devflow/work/1.md").is_file());
}

#[test]
fn a_hand_written_file_reads_with_its_defaults() {
    let (item, comments) = parse("12", "---\ntitle: Fix the login\n---\nBody\n").expect("read");
    assert_eq!(item.id, "12");
    assert_eq!((item.kind, item.state), (Kind::Item, State::Open));
    assert_eq!(item.body, "Body");
    assert!(comments.is_empty());
    assert!(parse("12", "no frontmatter").is_err());
    assert!(parse("12", "---\ntitle: x\nstate: later\n---\n").is_err());
}

#[test]
fn an_item_cut_or_merged_closes_and_says_how() {
    let root = tempfile::tempdir().expect("root");
    let items = Files::of(root.path());
    let one = items.create(&new("One"), at(0)).expect("one");
    let two = items.create(&new("Two"), at(1)).expect("two");
    let three = items.create(&new("Three"), at(2)).expect("three");
    let merged = items
        .close(&one.id, Closed::Into(two.id.clone()))
        .expect("merged");
    assert_eq!(merged.state, State::Done);
    assert_eq!(
        items.get(&one.id).expect("read").expect("there").closed,
        Some(Closed::Into(two.id.clone()))
    );
    assert!(
        items
            .close(&three.id, Closed::Into(one.id.clone()))
            .is_err(),
        "closed already"
    );
    assert!(
        items
            .close(&three.id, Closed::Into(three.id.clone()))
            .is_err(),
        "itself"
    );
    items.close(&three.id, Closed::Cut).expect("cut");
    assert_eq!(
        items.get(&three.id).expect("read").expect("there").closed,
        Some(Closed::Cut)
    );
}

#[test]
fn a_plan_waits_beside_its_epic() {
    let root = tempfile::tempdir().expect("root");
    let items = Files::of(root.path());
    assert_eq!(items.plan("1").expect("read"), None);
    let plan = serde_json::json!({ "cards": [{ "key": "s1", "title": "One" }], "edited": false });
    items.keep_plan("1", &plan).expect("kept");
    assert_eq!(items.plan("1").expect("read"), Some(plan));
    assert!(
        items.list().expect("list").is_empty(),
        "a plan is not an item"
    );
    assert!(items.keep_plan("../x", &serde_json::json!({})).is_err());
}

#[test]
fn a_tools_item_is_the_engines_card() {
    let params = serde_json::json!({ "item": "3", "checks": ["unit"] });
    assert_eq!(
        as_card(&params),
        serde_json::json!({ "card": "3", "checks": ["unit"] })
    );
    let both = serde_json::json!({ "item": "3", "card": "4" });
    assert_eq!(as_card(&both)["card"], "4");
}
