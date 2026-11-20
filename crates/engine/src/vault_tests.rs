use serde_json::json;

use super::*;

fn report() -> Value {
    json!({ "hypotheses": [
        { "id": "h1", "status": "confirmed",
          "exploit": { "path": "tests/session_forged.rs", "test": "forged", "saved": "exploits/h1/session_forged.rs" } },
        { "id": "h2", "status": "tried",
          "exploit": { "path": "../outside.rs", "test": "out", "saved": "exploits/h2/outside.rs" } },
        { "id": "h3", "status": "tried",
          "exploit": { "path": "linked/inside.rs", "test": "in", "saved": "exploits/h3/inside.rs" } },
        { "id": "h4", "status": "tried",
          "exploit": { "path": "tests/x.rs", "test": "x", "saved": "../../escape.rs" } },
    ] })
}

fn run_with_exploits(folder: &Path) {
    for (id, name) in [
        ("h1", "session_forged.rs"),
        ("h2", "outside.rs"),
        ("h3", "inside.rs"),
    ] {
        let at = folder.join("exploits").join(id);
        std::fs::create_dir_all(&at).expect("exploits");
        std::fs::write(at.join(name), format!("// {id}\n")).expect("exploit");
    }
}

#[test]
fn a_vault_is_never_inside_the_checkout() {
    let dir = tempfile::tempdir().expect("dir");
    let checkout = dir.path().join("repo");
    std::fs::create_dir_all(&checkout).expect("repo");
    let kept = home(&dir.path().join("cache"), &checkout).expect("outside");
    assert!(!kept.starts_with(checkout.canonicalize().expect("real")));
    let refused = home(&checkout.join(".cache"), &checkout).expect_err("inside");
    assert!(refused.contains("inside the checkout"), "{refused}");
    // A retro run's own exploits folder is held to the same.
    assert!(outside(&checkout.join(".cache/reviews/r/exploits"), &checkout).is_err());
    assert!(outside(&dir.path().join("cache/reviews/r/exploits"), &checkout).is_ok());
    // Nor through a link that leads into it.
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&checkout, dir.path().join("linked-cache")).expect("link");
        assert!(home(&dir.path().join("linked-cache"), &checkout).is_err());
    }
}

#[test]
fn promote_copies_an_exploit_into_the_repository_at_its_path() {
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().join("repo");
    let folder = dir.path().join("vault/run");
    std::fs::create_dir_all(&root).expect("repo");
    run_with_exploits(&folder);
    let at = promote(&root, &folder, &report(), "h1").expect("promoted");
    assert_eq!(at, "tests/session_forged.rs");
    assert_eq!(
        std::fs::read_to_string(root.join(&at)).expect("copied"),
        "// h1\n"
    );
    let again = promote(&root, &folder, &report(), "h1").expect_err("there already");
    assert!(again.contains("there already"), "{again}");
    assert!(promote(&root, &folder, &report(), "h9").is_err());
}

#[test]
fn promote_refuses_a_path_or_a_link_out_of_the_repository() {
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().join("repo");
    let folder = dir.path().join("vault/run");
    std::fs::create_dir_all(&root).expect("repo");
    run_with_exploits(&folder);
    assert!(promote(&root, &folder, &report(), "h2").is_err(), "../");
    assert!(!dir.path().join("outside.rs").exists());
    #[cfg(unix)]
    {
        let away = dir.path().join("away");
        std::fs::create_dir_all(&away).expect("away");
        std::os::unix::fs::symlink(&away, root.join("linked")).expect("link");
        let refused = promote(&root, &folder, &report(), "h3").expect_err("link out");
        assert!(refused.contains("leads out"), "{refused}");
        assert!(
            !away.join("inside.rs").exists(),
            "nothing written through the link"
        );
    }
    assert!(
        promote(&root, &folder, &report(), "h4").is_err(),
        "a kept file out of its run"
    );
    let mut hidden = report();
    hidden["hypotheses"][0]["exploit"]["path"] = json!(".github/workflows/x.yml");
    let refused = promote(&root, &folder, &hidden, "h1").expect_err("hidden");
    assert!(refused.contains("hidden"), "{refused}");
    assert!(!root.join(".github").exists());
}
