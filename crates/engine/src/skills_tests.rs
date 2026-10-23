use super::*;
use crate::config::STAGES;

const OURS: &str = "---\nname: devflow-plan\ndescription: Our own plan.\n---\n\nPlan our way.\n";

fn write(base: &Path, relative: &str, text: &str) {
    let path = base.join(relative);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("folder");
    std::fs::write(path, text).expect("write");
}

#[test]
fn every_stage_has_a_built_in_skill_that_names_itself() {
    let empty = tempfile::tempdir().expect("tempdir");
    let all = offered(&STAGES);
    assert_eq!(all, names().collect::<Vec<_>>());
    for stage in STAGES {
        assert!(
            all.contains(&format!("devflow-{stage}").as_str()),
            "{stage}"
        );
    }
    for name in all {
        let skill = resolve(empty.path(), empty.path(), name).expect(name);
        assert_eq!(skill.layer, Layer::BuiltIn);
        assert_eq!(skill.frontmatter["name"], name);
        assert_eq!(
            skill.entry()["uri"],
            format!("skill://devflow/{name}/SKILL.md")
        );
    }
}

#[test]
fn only_the_stages_switched_on_offer_their_skills() {
    assert_eq!(offered(&["plan"]), ["devflow-plan", "devflow-setup"]);
    assert_eq!(offered(&[]), ["devflow-setup"]);
}

#[test]
fn a_projects_skill_replaces_the_persons_which_replaces_the_built_in() {
    let project = tempfile::tempdir().expect("project");
    let personal = tempfile::tempdir().expect("personal");
    let resolved = || resolve(project.path(), personal.path(), "devflow-plan").expect("resolved");

    let mine = OURS.replace("Our own", "My own");
    write(personal.path(), "devflow-plan/SKILL.md", &mine);
    assert_eq!(resolved().layer, Layer::Personal);
    assert_eq!(resolved().text, mine);

    write(
        project.path(),
        ".devflow/skills/devflow-plan/SKILL.md",
        OURS,
    );
    assert_eq!(resolved().layer, Layer::Project);
    assert_eq!(resolved().text, OURS);
    assert_eq!(resolved().frontmatter["description"], "Our own plan.");

    // Another skill is untouched by either.
    let other = resolve(project.path(), personal.path(), "devflow-review").expect("review");
    assert_eq!(other.layer, Layer::BuiltIn);
}

#[test]
fn a_skill_is_listed_with_the_digest_and_size_of_its_file() {
    let project = tempfile::tempdir().expect("project");
    write(
        project.path(),
        ".devflow/skills/devflow-plan/SKILL.md",
        OURS,
    );
    let skill = resolve(project.path(), project.path(), "devflow-plan").expect("plan");
    assert_eq!(
        skill.entry(),
        json!({
            "uri": "skill://devflow/devflow-plan/SKILL.md",
            "frontmatter": { "name": "devflow-plan", "description": "Our own plan." },
            "resources": [{
                "uri": "skill://devflow/devflow-plan/SKILL.md",
                "digest": "sha256:529b1390994099b75e7e22760ab3ce3664cf2a5709d000dd1f831147b367f54b",
                "size": 69,
            }],
        })
    );
    assert_eq!(skill.to_json()["layer"], "project");
}

#[test]
fn a_skill_that_cannot_be_used_is_refused_rather_than_passed_over() {
    let project = tempfile::tempdir().expect("project");
    let at = ".devflow/skills/devflow-plan/SKILL.md";
    let refused = |project: &Path| resolve(project, project, "devflow-plan").expect_err("refused");

    write(
        project.path(),
        at,
        &OURS.replace("name: devflow-plan", "name: plan"),
    );
    assert!(refused(project.path()).contains("names it `plan`"));

    write(project.path(), at, "Plan our way.\n");
    assert!(refused(project.path()).contains("frontmatter"));

    let large = format!("{OURS}{}", "x".repeat(MOST_BYTES as usize));
    write(project.path(), at, &large);
    assert!(refused(project.path()).contains("larger than"));

    #[cfg(unix)]
    {
        let outside = tempfile::tempdir().expect("outside");
        write(outside.path(), "SKILL.md", OURS);
        std::fs::remove_file(project.path().join(at)).expect("remove");
        std::os::unix::fs::symlink(outside.path().join("SKILL.md"), project.path().join(at))
            .expect("link");
        assert!(refused(project.path()).contains("outside"));
    }
}

#[test]
fn a_skill_is_named_by_its_name_or_its_uri_and_nothing_else() {
    assert_eq!(named("devflow-plan"), Some("devflow-plan"));
    assert_eq!(
        named("skill://devflow/devflow-plan/SKILL.md"),
        Some("devflow-plan")
    );
    assert_eq!(named("../devflow-plan"), None);
    assert_eq!(named("skill://devflow/../SKILL.md"), None);
    let empty = tempfile::tempdir().expect("tempdir");
    assert!(resolve(empty.path(), empty.path(), "../../etc/passwd")
        .expect_err("not a skill")
        .contains("not a Devflow skill"));
}

#[test]
fn an_own_stage_reads_its_skill_where_it_already_is() {
    let project = tempfile::tempdir().expect("project");
    let installed = tempfile::tempdir().expect("installed");
    let skill = |name: &str| format!("---\nname: {name}\ndescription: Ours.\n---\nDo it.\n");
    write(project.path(), ".devflow/skills/pr/SKILL.md", &skill("pr"));
    write(
        project.path(),
        ".claude/skills/ticket/SKILL.md",
        &skill("ticket"),
    );
    write(installed.path(), "deploy/SKILL.md", &skill("deploy"));
    let places = Places {
        project: project.path(),
        personal: installed.path(),
        teams: &[],
        installed: Some(installed.path()),
    };
    assert_eq!(
        own("project/pr", &places).expect("project").layer,
        "project"
    );
    let ticket = own("skills/ticket", &places).expect("the project's own .claude skill");
    assert_eq!(
        ticket.file.as_deref(),
        Some(
            project
                .path()
                .join(".claude/skills/ticket/SKILL.md")
                .as_path()
        ),
        "read where it is, never copied"
    );
    assert_eq!(
        own("skills/deploy", &places).expect("installed").layer,
        "installed"
    );
    assert!(own("skills/nowhere", &places).is_err());
    assert!(own("acme/ticket", &places)
        .expect_err("no such layer")
        .contains("acme"));
    write(
        project.path(),
        ".devflow/skills/wrong/SKILL.md",
        &skill("other"),
    );
    assert!(
        own("project/wrong", &places).is_err(),
        "another name in its frontmatter"
    );
}

#[test]
fn a_card_is_closed_with_a_handoff_and_the_next_starts_in_a_fresh_session() {
    let empty = tempfile::tempdir().expect("tempdir");
    for name in ["devflow-execution", "devflow-completion"] {
        let text = resolve(empty.path(), empty.path(), name).expect(name).text;
        assert!(text.contains("devpit_handoff"), "{name}");
        assert!(text.contains("next card"), "{name}");
        assert!(text.contains("**fresh session**"), "{name}");
    }
}

#[test]
fn a_record_names_this_devpit_and_the_text_of_each_skill_it_followed() {
    let made = made_by(&["devflow-review", "not-a-skill"]);
    assert_eq!(made["version"], env!("CARGO_PKG_VERSION"));
    let shipped = include_str!("../../../flow/skills/devflow-review/SKILL.md");
    assert_eq!(
        made["skills"],
        json!({ "devflow-review": format!("sha256:{:x}", Sha256::digest(shipped.as_bytes())) })
    );
}

#[test]
fn a_project_on_devpits_folder_keeps_its_skills_there() {
    let project = tempfile::tempdir().expect("project");
    let personal = tempfile::tempdir().expect("personal");
    write(project.path(), crate::locate::DEVPIT, "version: 2\n");
    write(
        project.path(),
        ".devpit/devflow/skills/devflow-plan/SKILL.md",
        OURS,
    );
    let skill = resolve(project.path(), personal.path(), "devflow-plan").expect("resolved");
    assert_eq!(skill.layer, Layer::Project);
    assert_eq!(skill.text, OURS);
}
