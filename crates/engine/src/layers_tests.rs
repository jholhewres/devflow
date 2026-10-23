use std::path::Path;
use std::process::Command;

use super::*;
use crate::config::Extend;
use crate::pinning;

fn git(dir: &Path, args: &[&str]) {
    let ran = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.email=team@example.invalid",
            "-c",
            "user.name=Team",
        ])
        .args(["-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"])
        .args(args)
        .output()
        .expect("git");
    assert!(
        ran.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&ran.stderr)
    );
}

fn write(base: &Path, relative: &str, text: &str) {
    let path = base.join(relative);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("folder");
    std::fs::write(path, text).expect("write");
}

const TEAM_V1: &str = "version: 2
review:
  reviewers:
    - agent: claude
      persona: devflow-security
locked: [review.reviewers.devflow-security]
";

const TEAM_V2: &str = "version: 2
review:
  reviewers:
    - agent: claude
      persona: devflow-security
    - agent: codex
      persona: devflow-spec
locked: [review.reviewers.devflow-security]
";

/// A team's layer as a bare repository, the way a project reaches one: tag
/// v1, then v2 adding a reviewer.
fn team(base: &Path) -> String {
    let work = base.join("work");
    std::fs::create_dir_all(&work).expect("work");
    git(&work, &["init", "-q", "--initial-branch=main"]);
    write(&work, "devflow.yaml", TEAM_V1);
    write(
        &work,
        "skills/ticket/SKILL.md",
        "---\nname: ticket\ndescription: Open the ticket.\n---\nOne.\n",
    );
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-qm", "one"]);
    git(&work, &["tag", "v1"]);
    write(&work, "devflow.yaml", TEAM_V2);
    git(&work, &["commit", "-qam", "two"]);
    git(&work, &["tag", "v2"]);
    let bare = base.join("acme").join("devflow.git");
    let cloned = Command::new("git")
        .args(["clone", "-q", "--bare"])
        .arg(&work)
        .arg(&bare)
        .output()
        .expect("clone");
    assert!(cloned.status.success());
    bare.display().to_string()
}

fn project(url: &str, reference: &str, more: &str) -> String {
    format!("version: 2\nextends:\n  - git: {url}\n    ref: {reference}\n{more}")
}

fn agents(layered: &Layered) -> Vec<&'static str> {
    layered
        .config
        .review
        .reviewers
        .iter()
        .map(|one| one.agent.word())
        .collect()
}

#[test]
fn a_teams_layer_applies_only_at_the_commit_the_person_approved() {
    let base = tempfile::tempdir().expect("tempdir");
    let url = team(base.path());
    let root = base.path().join("project");
    std::fs::create_dir_all(&root).expect("project");
    let home = Home::under(&base.path().join("devpit-home"));
    let v1 = Extend {
        git: url.clone(),
        reference: "v1".into(),
    };

    // Never approved: nothing of it applies.
    let text = project(&url, "v1", "");
    let before = layered(&root, &text, &home).expect("reads");
    assert_eq!(before.teams[0].state, "approve");
    assert!(agents(&before).is_empty());
    assert_eq!(before.teams[0].name, "acme");

    let shown = pinning::fetched(&root, &v1, &home).expect("fetched");
    assert!(shown
        .files
        .contains(&("skills/ticket/SKILL.md".to_owned(), "added")));
    assert!(
        layered(&root, &text, &home)
            .expect("reads")
            .applied
            .is_empty(),
        "fetching applied it"
    );
    pinning::approve(&root, &v1, &shown.to_commit, &home).expect("approved");
    let approved = layered(&root, &text, &home).expect("reads");
    assert_eq!(approved.teams[0].state, "applied");
    assert_eq!(agents(&approved), ["claude"]);
    assert_eq!(
        approved.applied[0]
            .read("skills/ticket/SKILL.md")
            .expect("read")
            .as_deref(),
        Some("---\nname: ticket\ndescription: Open the ticket.\n---\nOne.\n")
    );

    // The ref moved in devflow.yaml: what was approved still applies, nothing of v2.
    let moved = project(&url, "v2", "");
    let waiting = layered(&root, &moved, &home).expect("reads");
    assert_eq!(waiting.teams[0].state, "approve");
    assert_eq!(
        agents(&waiting),
        ["claude"],
        "v2 applied without the person's approval"
    );

    let v2 = Extend {
        git: url.clone(),
        reference: "v2".into(),
    };
    let change = pinning::fetched(&root, &v2, &home).expect("fetched");
    assert_eq!(change.from_ref.as_deref(), Some("v1"));
    assert!(
        change
            .diff
            .iter()
            .any(|line| line.contains("+       persona: devflow-spec")),
        "{:?}",
        change.diff
    );
    assert_eq!(
        agents(&layered(&root, &moved, &home).expect("reads")),
        ["claude"]
    );
    pinning::approve(&root, &v2, &change.to_commit, &home).expect("approved");
    assert_eq!(
        agents(&layered(&root, &moved, &home).expect("reads")),
        ["claude", "codex"]
    );
}

#[test]
fn the_project_cannot_switch_off_a_reviewer_the_team_locked() {
    let base = tempfile::tempdir().expect("tempdir");
    let url = team(base.path());
    let root = base.path().join("project");
    std::fs::create_dir_all(&root).expect("project");
    let home = Home::under(&base.path().join("devpit-home"));
    let v1 = Extend {
        git: url.clone(),
        reference: "v1".into(),
    };
    let shown = pinning::fetched(&root, &v1, &home).expect("fetched");
    pinning::approve(&root, &v1, &shown.to_commit, &home).expect("approved");

    let off = project(
        &url,
        "v1",
        "review:\n  reviewers:\n    - agent: codex\n      persona: devflow-spec\n",
    );
    let refused = layered(&root, &off, &home).expect_err("the lock holds");
    assert_eq!(refused.field, "review.reviewers.devflow-security");
    assert!(refused.message.contains("locked by acme"), "{refused}");
    // Keeping the locked reviewer and adding one is not weakening it.
    let kept = project(
        &url,
        "v1",
        "review:\n  reviewers:\n    - agent: claude\n      persona: devflow-security\n    - agent: gemini\n      persona: devflow-spec\n",
    );
    assert_eq!(
        agents(&layered(&root, &kept, &home).expect("reads")),
        ["claude", "gemini"]
    );
}

#[test]
fn a_file_whose_hash_changed_since_the_approval_is_refused() {
    let base = tempfile::tempdir().expect("tempdir");
    let url = team(base.path());
    let root = base.path().join("project");
    std::fs::create_dir_all(&root).expect("project");
    let home = Home::under(&base.path().join("devpit-home"));
    let v1 = Extend {
        git: url.clone(),
        reference: "v1".into(),
    };
    let shown = pinning::fetched(&root, &v1, &home).expect("fetched");
    pinning::approve(&root, &v1, &shown.to_commit, &home).expect("approved");
    let mut lock = read_lock(&root).expect("lock");
    lock.extends[0]
        .files
        .insert("devflow.yaml".into(), "sha256:0".into());
    write_lock(&root, &lock).expect("written");
    let refused = layered(&root, &project(&url, "v1", ""), &home).expect_err("tampered");
    assert!(
        refused.message.contains("not what was approved"),
        "{refused}"
    );
}

#[test]
fn a_layer_is_named_by_the_owner_in_its_address() {
    assert_eq!(name_of("git@bitbucket.org:acme/devpit-devflow.git"), "acme");
    assert_eq!(name_of("https://github.com/Acme-Co/flow"), "acme-co");
    assert_eq!(name_of("/srv/git/acme/devflow.git"), "acme");
}

/// A team layer holding one persona of its own, approved at v1.
fn a_team_with_a_persona(base: &Path, root: &Path, home: &Home) -> Vec<Team> {
    let work = base.join("persona-work");
    std::fs::create_dir_all(&work).expect("work");
    git(&work, &["init", "-q", "--initial-branch=main"]);
    write(&work, "devflow.yaml", "version: 2\n");
    write(
        &work,
        "reviewers/acme-style.md",
        "---\nname: acme-style\n---\nThe company's way.",
    );
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-qm", "one"]);
    git(&work, &["tag", "v1"]);
    let bare = base.join("acme").join("review.git");
    let cloned = Command::new("git")
        .args(["clone", "-q", "--bare"])
        .arg(&work)
        .arg(&bare)
        .output()
        .expect("clone");
    assert!(cloned.status.success());
    let url = bare.display().to_string();
    let v1 = Extend {
        git: url.clone(),
        reference: "v1".into(),
    };
    let shown = pinning::fetched(root, &v1, home).expect("fetched");
    pinning::approve(root, &v1, &shown.to_commit, home).expect("approved");
    layered(root, &project(&url, "v1", ""), home)
        .expect("reads")
        .applied
}

#[test]
fn a_persona_comes_from_the_project_then_its_team_then_the_person() {
    use crate::review::{persona_text, Personas};

    let base = tempfile::tempdir().expect("tempdir");
    let root = base.path().join("project");
    std::fs::create_dir_all(&root).expect("project");
    let home = Home::under(&base.path().join("devpit-home"));
    let teams = a_team_with_a_persona(base.path(), &root, &home);
    let mine = base.path().join("devpit-home/devflow/reviewers");
    write(
        &mine,
        "acme-style.md",
        "---\nname: acme-style\n---\nMy way.",
    );
    write(&mine, "my-style.md", "---\nname: my-style\n---\nOnly mine.");
    let everywhere = Personas {
        personal: Some(&mine),
        teams: &teams,
    };

    // The person's own, in a project with no team: their way follows them.
    let alone = Personas {
        personal: Some(&mine),
        teams: &[],
    };
    assert!(persona_text(&root, alone, "acme-style")
        .expect("mine")
        .ends_with("My way."));
    // The company's layer is read over the person's, for its own projects.
    assert!(persona_text(&root, everywhere, "acme-style")
        .expect("the team's")
        .ends_with("The company's way."));
    assert!(persona_text(&root, everywhere, "my-style")
        .expect("mine")
        .ends_with("Only mine."));
    // The project's own file wins over both.
    write(
        &root,
        ".devflow/reviewers/acme-style.md",
        "---\nname: acme-style\n---\nThis repo's.",
    );
    assert!(persona_text(&root, everywhere, "acme-style")
        .expect("the project's")
        .ends_with("This repo's."));
    // devpit's own stays underneath all of them.
    assert!(persona_text(&root, everywhere, "devflow-spec")
        .expect("built in")
        .contains("Devflow reviewer: Spec"));
    assert!(persona_text(&root, Personas::default(), "my-style").is_err());
}

#[test]
fn a_project_without_a_file_reviews_with_the_persons_reviewers() {
    let base = tempfile::tempdir().expect("tempdir");
    let home = Home::under(base.path());
    let bare = personal_only(&home).expect("the defaults");
    assert!(bare.review.reviewers.is_empty());
    write(&home.personal, LAYER_FILE, TEAM_V2);
    let mine = personal_only(&home).expect("the person's");
    let personas: Vec<&str> = mine
        .review
        .reviewers
        .iter()
        .map(|one| one.persona.as_str())
        .collect();
    assert_eq!(personas, ["devflow-security", "devflow-spec"]);
    assert!(!mine.enabled, "a layer never switches a project on");
}
