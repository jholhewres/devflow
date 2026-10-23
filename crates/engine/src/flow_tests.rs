use crate::config::{parse, Approve, Config, Publish, StageGate, V1, VERSION};
use crate::render::render;

const EXAMPLE: &str = "version: 2
extends:
  - git: git@bitbucket.org:acme/devpit-devflow.git
    ref: v1.4.0
stages:
  - uses: acme/ticket
  - uses: builtin/context
  - uses: builtin/plan
    publish: board        # board | jira | linear | github
  - uses: builtin/execution
  - uses: builtin/review
  - uses: acme/pr
    gate: { command: \"./scripts/pr-checklist.sh\" }
locked: [review.reviewers.devflow-security, decisions.use]
";

#[test]
fn version_two_lists_own_stages_beside_the_built_in_ones() {
    let config = parse(EXAMPLE).expect("the card's example reads");
    let names: Vec<&str> = config.flow.iter().map(|step| step.name()).collect();
    assert_eq!(
        names,
        ["ticket", "context", "plan", "execution", "review", "pr"]
    );
    // Left out of the list is off.
    assert_eq!(
        config.stages_on(),
        ["context", "plan", "execution", "review"]
    );
    assert!(!config.stages.briefing.enabled && !config.stages.completion.enabled);
    assert_eq!(config.publish(), Publish::Board);
    assert_eq!(config.extends[0].reference, "v1.4.0");
    assert_eq!(
        config.locked,
        ["review.reviewers.devflow-security", "decisions.use"]
    );
    let pr = &config.flow[5];
    assert_eq!(
        pr.own.as_ref().and_then(|own| own.gate.clone()),
        Some(StageGate::Command("./scripts/pr-checklist.sh".into()))
    );
    assert_eq!(config.own_on().len(), 2);
}

#[test]
fn version_one_is_still_read_and_stays_version_one() {
    let config = parse("version: 1\nstages:\n  plan:\n    approve: none\n").expect("v1 reads");
    assert_eq!(config.version, V1);
    assert_eq!(config.stages.plan.approve, Approve::Nobody);
    assert_eq!(config.stages_on().len(), 6);
    assert!(render(&config).contains("  plan:\n    enabled: true\n    approve: none\n"));
    // A list, `extends` or `locked` in a version 1 file is a hand edit to fix.
    let list = parse("version: 1\nstages:\n  - uses: builtin/plan\n").expect_err("v1 has no list");
    assert_eq!((list.line, list.field.as_str()), (Some(3), "stages"));
    assert!(list.message.contains("version: 2"), "{list}");
}

#[test]
fn a_change_through_devpit_that_needs_version_two_writes_it() {
    let v1 = parse("version: 1\n").expect("v1");
    let mut json = v1.to_json();
    json["extends"] = serde_json::json!([{ "git": "/teams/acme.git", "ref": "v1" }]);
    let upgraded = crate::config::from_json(&json).expect("upgraded");
    assert_eq!(upgraded.version, VERSION);
    assert!(render(&upgraded).starts_with("# Devflow"));
    assert!(render(&upgraded).contains("\nversion: 2\n"));
}

#[test]
fn what_version_two_writes_reads_back_the_same() {
    let mut config = parse(EXAMPLE).expect("reads");
    config.stages.plan.publish = Some(Publish::Board);
    let text = render(&config);
    assert_eq!(parse(&text), Ok(config.clone()), "{text}");
    assert_eq!(crate::config::from_json(&config.to_json()), Ok(config));
    assert_eq!(parse(&render(&Config::default())), Ok(Config::default()));
}

#[test]
fn a_stage_is_named_once_and_says_what_it_uses() {
    let twice = parse("version: 2\nstages:\n  - uses: builtin/plan\n  - uses: acme/plan\n")
        .expect_err("twice");
    assert_eq!(twice.field, "stages.1.uses");
    let unknown = parse("version: 2\nstages:\n  - uses: builtin/shipping\n").expect_err("no such");
    assert!(unknown.message.contains("not a stage"), "{unknown}");
    let gate =
        parse("version: 2\nstages:\n  - uses: builtin/completion\n    gate: { command: x }\n")
            .expect_err("completion is a rubric");
    assert_eq!(gate.field, "stages.completion.gate");
}

#[test]
fn a_stage_is_reached_by_its_name_in_either_version() {
    let v2 = parse(EXAMPLE).expect("reads");
    let off = crate::preset::with_set(&v2, "stages.pr.enabled", &serde_json::json!(false))
        .expect("set by name");
    assert!(!off.is_on(&off.flow[5]));
    let set = crate::preset::with_set(&v2, "stages.plan.publish", &serde_json::json!("jira"))
        .expect("set by name");
    let changes = crate::preset::changes(Some(&v2), &set);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].path, "stages.plan.publish");
    // In place, so the person's comment stays.
    let (text, laid_out) = crate::folder::rewritten(Some(EXAMPLE), &changes, &set);
    assert!(!laid_out, "{text}");
    assert!(
        text.contains("publish: jira        # board | jira | linear | github"),
        "{text}"
    );
}
