use super::*;

fn refused(text: &str) -> Invalid {
    parse(text).expect_err("refused")
}

#[test]
fn a_file_of_one_line_takes_every_default() {
    assert_eq!(parse("version: 2\n"), Ok(Config::default()));
    assert_eq!(
        parse("version: 1\n"),
        Ok(Config {
            version: V1,
            ..Config::default()
        })
    );
    let defaults = Config::default();
    assert!(!defaults.enabled);
    assert_eq!(defaults.stages.plan.approve, Approve::Person);
    assert_eq!(defaults.stages.completion.gate, "devflow-done");
    assert_eq!(
        defaults.review.block_on,
        [Severity::Critical, Severity::High]
    );
    assert_eq!(defaults.decisions.mode, Mode::Shadow);
}

/// A file a newer devpit wrote, with a field this one does not know, still
/// reads: the field is named with its line and left out, the rest kept.
#[test]
fn a_field_this_version_does_not_read_is_told_and_the_rest_is_read() {
    let text = "version: 1\nenabled: true\nstages:\n  plan:\n    aprove: person\n    requires: x\n";
    let read = parse(text).expect("still reads");
    assert!(read.enabled);
    assert_eq!(read.version, V1);
    let told = unread(text);
    assert_eq!(told.len(), 2);
    assert_eq!(told[0].line, Some(5));
    assert_eq!(told[0].field, "stages.plan.aprove");
    assert!(told[0].message.contains("enabled, approve"), "{}", told[0]);
    assert!(unread("version: 2\n").is_empty());
}

/// A change made through devpit is refused instead: its caller can fix it.
#[test]
fn a_change_naming_a_field_this_version_does_not_read_is_refused() {
    let invalid = from_json(&serde_json::json!({
        "version": 2, "stages": { "plan": { "aprove": "person" } }
    }))
    .expect_err("refused");
    assert_eq!(invalid.field, "stages.plan.aprove");
}

#[test]
fn a_word_outside_its_list_says_the_words_it_takes() {
    let invalid = refused("version: 1\ndecisions:\n  use: true\n  mode: strict\n");
    assert_eq!(invalid.line, Some(4));
    assert_eq!(invalid.field, "decisions.mode");
    assert!(invalid.message.contains("shadow, enforce"), "{invalid}");
    assert_eq!(
        invalid.to_string(),
        "line 4, `decisions.mode`: `strict` is not one of shadow, enforce"
    );
}

#[test]
fn the_version_is_required_and_only_one_this_devpit_knows_is_read() {
    assert_eq!(refused("enabled: true\n").field, "version");
    assert_eq!(refused("").field, "version");
    let later = refused("version: 3\n");
    assert_eq!((later.line, later.field.as_str()), (Some(1), "version"));
}

#[test]
fn a_check_is_named_once_and_runs_one_line() {
    let twice = refused(
        "version: 1\nstages:\n  execution:\n    checks:\n      - { name: unit, run: make test }\n      - { name: unit, run: cargo test }\n",
    );
    assert_eq!(twice.field, "stages.execution.checks.1.name");
    assert_eq!(twice.line, Some(6));
    let nameless = refused("version: 1\nstages:\n  execution:\n    checks:\n      - run: make\n");
    assert_eq!(nameless.field, "stages.execution.checks.0.name");
    let read = parse(
        "version: 1\nstages:\n  execution:\n    checks:\n      - name: e2e\n        run: pnpm e2e\n        report: junit\n        evidence: [screenshots, video]\n",
    )
    .expect("valid");
    assert_eq!(
        read.stages.execution.checks,
        [Check {
            name: "e2e".into(),
            run: "pnpm e2e".into(),
            report: Report::Junit,
            evidence: vec![Evidence::Screenshots, Evidence::Video],
            requires: None,
            exclusive: None,
        }]
    );
}

#[test]
fn the_e2e_folder_stays_inside_the_project() {
    for outside in ["/tmp/e2e", "../e2e", "specs/../../e2e", ".git/hooks"] {
        let text = format!("version: 1\nstages:\n  execution:\n    e2e_dir: {outside}\n");
        assert_eq!(
            refused(&text).field,
            "stages.execution.e2e_dir",
            "{outside}"
        );
    }
}

#[test]
fn a_reviewer_names_a_known_cli_and_a_persona() {
    let read = parse(
        "version: 1\nreview:\n  reviewers:\n    - agent: codex\n      persona: devflow-standards\n      model: gpt-5\n  block_on: [critical]\n",
    )
    .expect("valid");
    assert_eq!(read.review.reviewers[0].agent, Agent::Codex);
    assert_eq!(read.review.reviewers[0].model.as_deref(), Some("gpt-5"));
    assert_eq!(read.review.block_on, [Severity::Critical]);
    let unknown =
        refused("version: 1\nreview:\n  reviewers:\n    - agent: copilot\n      persona: x\n");
    assert_eq!(unknown.field, "review.reviewers.0.agent");
}

#[test]
fn several_reviewers_are_consolidated_by_jev_unless_the_file_says_otherwise() {
    assert_eq!(
        parse("version: 1\n").expect("valid").review.consolidate,
        Consolidate::Jev
    );
    let read = parse("version: 1\nreview:\n  consolidate: none\n").expect("valid");
    assert_eq!(read.review.consolidate, Consolidate::Nothing);
    let wrong = refused("version: 1\nreview:\n  consolidate: vote\n");
    assert_eq!(wrong.field, "review.consolidate");
    assert!(
        wrong.message.contains("jev, agent, none"),
        "{}",
        wrong.message
    );
}

#[test]
fn the_review_asks_for_no_poc_run_unless_the_file_says_verify() {
    let verify = |text: &str| parse(text).expect("valid").review.verify;
    assert_eq!(verify("version: 1\n"), Verify::Off);
    assert_eq!(verify("version: 2\n"), Verify::Off);
    assert_eq!(
        verify("version: 1\nreview:\n  verify: advise\n"),
        Verify::Advise
    );
    assert_eq!(
        verify("version: 2\nreview:\n  verify: required\n"),
        Verify::Required
    );
    let wrong = refused("version: 2\nreview:\n  verify: always\n");
    assert_eq!(wrong.field, "review.verify");
    assert!(wrong.message.contains("off, advise, required"), "{wrong}");
}

#[test]
fn the_review_is_scaled_only_when_the_file_asks() {
    let scale = |text: &str| parse(text).expect("valid").review.scale;
    assert_eq!(scale("version: 2\n"), None);
    assert_eq!(scale("version: 2\nreview:\n  scale: false\n"), None);
    assert_eq!(
        scale("version: 2\nreview:\n  scale: true\n"),
        Some(crate::scale::Scale::default())
    );
    let own =
        scale("version: 2\nreview:\n  scale:\n    small_lines: 30\n    sensitive: [\"db/**\"]\n")
            .expect("on");
    assert_eq!(own.small_lines, 30);
    assert_eq!(own.sensitive, ["db/**"]);
    let wrong = refused("version: 2\nreview:\n  scale:\n    small_lines: 0\n");
    assert_eq!(wrong.field, "review.scale.small_lines");
}

#[test]
fn rubrics_are_named_per_stage() {
    let read =
        parse("version: 1\ndecisions:\n  rubrics:\n    completion: devflow-done\n").expect("valid");
    assert_eq!(read.decisions.rubrics["completion"], "devflow-done");
    assert_eq!(
        refused("version: 1\ndecisions:\n  rubrics:\n    shipping: x\n").field,
        "decisions.rubrics.shipping"
    );
}

#[test]
fn yaml_that_does_not_parse_says_its_line() {
    let invalid = refused("version: 1\nstages:\n  plan: [unclosed\n");
    assert!(invalid.line.is_some(), "{invalid}");
    assert_eq!(refused("version: 1\nversion: 1\n").line, Some(2));
}

#[test]
fn anchors_and_second_documents_are_not_read() {
    let anchored = refused("version: 1\nstages: &s\n  plan: { enabled: true }\nreview: *s\n");
    assert!(anchored.message.contains("anchors"), "{anchored}");
    let two = refused("version: 1\n---\nversion: 1\n");
    assert!(two.message.contains("one document"), "{two}");
}

#[test]
fn a_quoted_true_is_a_word_not_a_switch() {
    assert_eq!(refused("version: 1\nenabled: \"true\"\n").field, "enabled");
    assert!(parse("version: 1\nenabled: true\n").expect("valid").enabled);
}

#[test]
fn the_stages_switched_on_keep_their_order() {
    let read =
        parse("version: 1\nstages:\n  context: { enabled: false }\n  review: { enabled: false }\n")
            .expect("valid");
    assert_eq!(
        read.stages_on(),
        ["briefing", "plan", "execution", "completion"]
    );
}

#[test]
fn a_card_releases_the_cards_waiting_on_it_once_done_unless_the_plan_says_its_gate() {
    let unblock_on = |text: &str| parse(text).expect("valid").unblock_on();
    assert_eq!(unblock_on("version: 1\n"), UnblockOn::Done);
    assert_eq!(unblock_on("version: 2\n"), UnblockOn::Done);
    let v1 = "version: 1\nstages:\n  plan:\n    unblock_on: gate\n";
    assert_eq!(unblock_on(v1), UnblockOn::Gate);
    let v2 = "version: 2\nstages:\n  - uses: builtin/plan\n    unblock_on: gate\n";
    assert_eq!(unblock_on(v2), UnblockOn::Gate);
    // Written back as it was said, in either version.
    for text in [v1, v2] {
        let config = parse(text).expect("valid");
        assert_eq!(
            parse(&crate::render::render(&config))
                .expect("rendered")
                .unblock_on(),
            UnblockOn::Gate
        );
        assert_eq!(from_json(&config.to_json()).expect("json"), config);
    }
    let wrong = refused("version: 1\nstages:\n  plan:\n    unblock_on: review\n");
    assert_eq!(wrong.field, "stages.plan.unblock_on");
    assert!(wrong.message.contains("done, gate"), "{wrong}");
    // Only the plan's.
    let told = unread("version: 1\nstages:\n  briefing:\n    unblock_on: gate\n");
    assert_eq!(told[0].field, "stages.briefing.unblock_on");
}
