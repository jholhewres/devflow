//! The engine as a library: a caller that keeps its work items its own way
//! (here in memory, as devpit keeps them on its board) takes one through
//! brief, plan, evidence and gate with nothing but the engine's API.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use devflow_engine::config::{Check, Config, Report};
use devflow_engine::evidence::{self, Card, Given};
use devflow_engine::gate::{self, Gate, Looked, Review, Run};
use devflow_engine::runner::Context;
use devflow_engine::runs::Runs;
use devflow_engine::work::{Closed, Comment, Kind, New, State, WorkItem, WorkItems};
use devflow_engine::{brief, criteria, plan};
use serde_json::json;

/// Work items in a map, as a board would hold them.
#[derive(Default)]
struct Memory {
    items: RefCell<BTreeMap<String, WorkItem>>,
    said: RefCell<Vec<(String, Comment)>>,
}

impl Memory {
    fn changed(&self, id: &str, change: impl FnOnce(&mut WorkItem)) -> Result<WorkItem, String> {
        let mut items = self.items.borrow_mut();
        let item = items.get_mut(id).ok_or(format!("no item {id}"))?;
        change(item);
        Ok(item.clone())
    }
}

impl WorkItems for Memory {
    fn get(&self, id: &str) -> Result<Option<WorkItem>, String> {
        Ok(self.items.borrow().get(id).cloned())
    }

    fn list(&self) -> Result<Vec<WorkItem>, String> {
        Ok(self.items.borrow().values().cloned().collect())
    }

    fn create(&self, new: &New, _at: SystemTime) -> Result<WorkItem, String> {
        let id = format!("card_{}", self.items.borrow().len() + 1);
        let item = WorkItem {
            id: id.clone(),
            title: new.title.clone(),
            kind: new.kind,
            state: State::Open,
            parent: new.parent.clone(),
            depends_on: new.depends_on.clone(),
            created: "20261030T120000Z".to_owned(),
            closed: None,
            body: new.body.clone(),
        };
        self.items.borrow_mut().insert(id, item.clone());
        Ok(item)
    }

    fn update_body(&self, id: &str, body: &str) -> Result<WorkItem, String> {
        self.changed(id, |item| item.body = body.to_owned())
    }

    fn retitle(&self, id: &str, title: &str) -> Result<WorkItem, String> {
        self.changed(id, |item| item.title = title.to_owned())
    }

    fn set_state(&self, id: &str, state: State) -> Result<WorkItem, String> {
        self.changed(id, |item| item.state = state)
    }

    fn comment(&self, id: &str, by: &str, text: &str, _at: SystemTime) -> Result<(), String> {
        let comment = Comment {
            by: by.to_owned(),
            at: "20261030T120000Z".to_owned(),
            text: text.to_owned(),
        };
        self.said.borrow_mut().push((id.to_owned(), comment));
        Ok(())
    }

    fn comments(&self, id: &str) -> Result<Vec<Comment>, String> {
        Ok(self
            .said
            .borrow()
            .iter()
            .filter(|(on, _)| on == id)
            .map(|(_, comment)| comment.clone())
            .collect())
    }

    fn close(&self, id: &str, closed: Closed) -> Result<WorkItem, String> {
        self.changed(id, |item| item.closed = Some(closed))
    }
}

const PASSING: &str = r#"printf '<testsuite><testcase classname="cli" name="rename changes the title"/></testsuite>' > "$DEVFLOW_REPORT_DIR/report.xml""#;

#[test]
fn an_item_kept_in_memory_goes_from_brief_to_a_passing_gate() {
    let board = Memory::default();
    let at = UNIX_EPOCH + Duration::from_secs(1_793_000_000);

    // The brief, written into the epic's body.
    let said = brief::Brief {
        goal: Some("Rename a card from the board".to_owned()),
        ..brief::Brief::default()
    };
    let epic = board
        .create(
            &New {
                title: brief::epic_title("Rename"),
                kind: Kind::Epic,
                parent: None,
                depends_on: Vec::new(),
                body: brief::written("Rename a card.", &said),
            },
            at,
        )
        .expect("the epic");
    assert_eq!(
        brief::read(&epic.body)
            .and_then(|kept| kept.goal)
            .as_deref(),
        Some("Rename a card from the board")
    );

    // The plan, one slice made an item under the epic.
    let slices = plan::read(&json!([{
        "key": "rename",
        "title": "Rename changes the title",
        "criteria": ["rename changes the title"],
        "verify": "cargo test",
    }]))
    .expect("the plan");
    plan::checked(&slices).expect("a plan that holds");
    let item = board
        .create(
            &New {
                title: plan::title(&slices[0]),
                kind: Kind::Item,
                parent: Some(epic.id.clone()),
                depends_on: Vec::new(),
                body: plan::body(&slices[0]),
            },
            at,
        )
        .expect("the item");
    let criteria: Vec<String> = criteria::criteria(&item.body)
        .into_iter()
        .map(|found| found.text)
        .collect();
    assert_eq!(criteria, ["rename changes the title"]);

    // Its checks, with the runs kept where the caller says.
    let dir = tempfile::tempdir().expect("a checkout");
    let root = dir.path();
    let runs = Runs {
        home: root.join("caller-home"),
        checkout: root.to_path_buf(),
    };
    let mut config = Config::default();
    config.stages.execution.checks = vec![Check {
        name: "unit".into(),
        run: PASSING.into(),
        report: Report::Junit,
        evidence: Vec::new(),
        requires: None,
        exclusive: None,
    }];
    let asked = evidence::asked(&json!({
        "item": item.id,
        "criteria": [{ "criterion": "rename changes the title", "tests": ["cli::rename changes the title"] }],
    }))
    .expect("asked");
    let context = Context {
        item: item.id.clone(),
        item_title: item.title.clone(),
        ..Context::default()
    };
    let ran = evidence::gathered(&Given {
        root,
        runs: &runs,
        locks: &root.join("caller-home/locks"),
        config: &config,
        asked: &asked,
        card: Card {
            id: &item.id,
            title: &item.title,
            body: &item.body,
        },
        context: &context,
        budget: Duration::from_secs(60),
        redact: &|text: &str| text.to_owned(),
        at,
    })
    .expect("a run");
    assert!(ran.green(), "{ran:?}");
    assert!(root.join("caller-home").join(&item.id).is_dir());
    board
        .comment(&item.id, "devflow", &evidence::comment(&ran, &[]), at)
        .expect("said on the item");

    // The gate holds it until a review that blocks nothing, then lets it go.
    let recorded = evidence::recorded(&ran);
    let approved = json!({ "verdict": "approve", "findings": [], "pending": [] });
    let gated = |review: Option<Review>| {
        let checked = gate::checked(&Looked {
            config: &config,
            card: &item.id,
            criteria: &criteria,
            run: Some(Run {
                name: &ran.stamp,
                evidence: &recorded,
            }),
            review,
            changed: None,
            stages: &[],
            unreviewed: None,
            no_code: false,
        });
        Gate::new(checked, None, &ran.stamp)
    };
    let held = gated(None);
    assert!(!held.passed());
    assert!(
        held.checked.missing[0].contains("no review yet"),
        "{:?}",
        held.checked.missing
    );
    let gate = gated(Some(Review {
        at: &ran.stamp,
        findings: &approved,
    }));
    assert!(gate.passed(), "{:?}", gate.checked.missing);
    board
        .set_state(&item.id, State::Done)
        .expect("finished on its gate");
    assert_eq!(board.comments(&item.id).expect("comments").len(), 1);
    assert_eq!(
        board.get(&item.id).expect("read").map(|one| one.state),
        Some(State::Done)
    );
}
