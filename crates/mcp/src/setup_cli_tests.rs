use std::cell::RefCell;

use super::*;
use crate::consent::How;

use crate::ready::tests::devpits;

fn wizard() -> Wizard {
    Wizard {
        preset: "recommended".to_owned(),
        no_register: false,
        no_project: false,
        no_jev: false,
        attack: true,
        test: Some("sh \"$DEVFLOW_EXPLOIT\"".to_owned()),
        image: None,
    }
}

fn project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".devpit/devflow")).unwrap();
    std::fs::write(dir.path().join(".devpit/devflow/devflow.yaml"), devpits()).unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        "{ \"devDependencies\": { \"jest\": \"29\" } }",
    )
    .unwrap();
    dir
}

#[test]
fn the_attack_is_set_up_after_one_yes_on_a_terminal() {
    let dir = project();
    let consent = Consent::at(&dir.path().join("home"));
    let asked = RefCell::new(Vec::new());
    let yes = |question: &str| {
        asked.borrow_mut().push(question.to_owned());
        Ok(true)
    };
    attack(dir.path(), &wizard(), &consent, &yes).unwrap();
    assert_eq!(*asked.borrow(), ["Apply it?"], "one yes");
    let project = Project::at(dir.path());
    let State::Valid(text, config) = project.read() else {
        panic!("reads");
    };
    assert!(
        text.contains("# Switched on by the person's click in the devpit app"),
        "{text}"
    );
    let attack = &config.stages.attack;
    assert_eq!(
        attack.test.as_deref(),
        Some("sh \"$DEVFLOW_EXPLOIT\""),
        "the flag over what was found"
    );
    assert!(attack.budget.is_empty(), "no budget is written");
    assert!(consent.made(&project.root, Ask::Enable));
    let given = consent.given(&project.root);
    assert!(
        given.iter().all(|one| one.how == How::Terminal),
        "{given:?}"
    );
    assert!(given
        .iter()
        .any(|one| one.what == "enabled" && one.asked_for == "attack"));
}

#[test]
fn a_no_on_the_terminal_writes_nothing() {
    let dir = project();
    let consent = Consent::at(&dir.path().join("home"));
    attack(dir.path(), &wizard(), &consent, &|_| Ok(false)).unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.path().join(".devpit/devflow/devflow.yaml")).unwrap(),
        devpits()
    );
    assert!(!consent.made(&Project::at(dir.path()).root, Ask::Enable));
    let refused = attack(dir.path(), &wizard(), &consent, &|_| {
        Err("this needs your yes on a terminal".to_owned())
    });
    assert!(refused.is_err(), "no terminal, no yes");
}
