use super::*;

fn tree() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("src")).expect("create");
    std::fs::create_dir_all(dir.path().join(".git")).expect("create");
    for name in ["a.rs", "item100.rs", "item9.rs", "item99.rs"] {
        std::fs::write(dir.path().join("src").join(name), "").expect("write");
    }
    std::fs::write(dir.path().join("README.md"), "").expect("write");
    dir
}

#[test]
fn a_path_that_climbs_out_is_refused() {
    let dir = tree();
    let escape = resolve(dir.path(), "../..");
    assert!(matches!(escape, Err(TreeError::Outside { .. })), "escaped");
}

/// A string comparison passes this and a resolved one does not, which is
/// why the order in `resolve` is not an implementation detail.
#[cfg(unix)]
#[test]
fn a_symlink_pointing_outside_is_refused() {
    let dir = tree();
    let outside = tempfile::tempdir().expect("tempdir");
    std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).expect("symlink");

    let followed = resolve(dir.path(), "escape");
    assert!(
        matches!(followed, Err(TreeError::Outside { .. })),
        "a symlink walked out of the project"
    );
}

#[test]
fn a_file_in_the_project_comes_back_relative() {
    let dir = tree();
    let dropped = dir.path().join("src/a.rs");
    assert_eq!(
        relative_to(dir.path(), &dropped).expect("relative"),
        "src/a.rs"
    );
}

#[test]
fn a_file_outside_the_project_is_refused() {
    let dir = tree();
    let elsewhere = tempfile::tempdir().expect("tempdir");
    std::fs::write(elsewhere.path().join("secret"), "").expect("write");
    let refused = relative_to(dir.path(), &elsewhere.path().join("secret"));
    assert!(matches!(refused, Err(TreeError::Outside { .. })));
}

#[test]
fn a_symlink_pointing_out_of_the_project_is_refused() {
    let dir = tree();
    let elsewhere = tempfile::tempdir().expect("tempdir");
    std::fs::write(elsewhere.path().join("secret"), "").expect("write");
    let link = dir.path().join("looks-inside");
    std::os::unix::fs::symlink(elsewhere.path().join("secret"), &link).expect("symlink");
    assert!(matches!(
        relative_to(dir.path(), &link),
        Err(TreeError::Outside { .. })
    ));
}

#[test]
fn a_missing_files_existing_parent_still_resolves() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("src")).expect("create");

    let resolved = resolve_new(dir.path(), "src/gone.rs").expect("resolve");
    let root = dir.path().canonicalize().expect("canonicalize");
    assert_eq!(resolved, root.join("src/gone.rs"));
}

/// The guard this module exists for, and the reason it must be asserted by
/// variant: a non-existent escaping path fails for a different reason
/// (`Unreadable`, nothing there to canonicalise), and a test that only checks
/// `is_err()` would keep passing after the containment check itself broke.
#[test]
fn a_parent_that_climbs_out_is_refused_as_outside() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Reaches a real file so the failure is containment, not "not there". One
    // `..` per component climbs to `/` wherever the tempdir happens to live.
    let climb = "../".repeat(dir.path().components().count());
    let refused = resolve_new(dir.path(), &format!("{climb}etc/passwd"));
    assert!(
        matches!(refused, Err(TreeError::Outside { .. })),
        "wrong reason: {refused:?}"
    );
}

#[test]
fn a_bare_name_at_the_root_resolves_against_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let resolved = resolve_new(dir.path(), "new.txt").expect("resolve");
    assert_eq!(
        resolved,
        dir.path()
            .canonicalize()
            .expect("canonicalize")
            .join("new.txt")
    );
}

#[test]
fn a_trailing_dot_dot_is_refused_without_reaching_the_filesystem() {
    let dir = tempfile::tempdir().expect("tempdir");
    assert!(matches!(
        resolve_new(dir.path(), ".."),
        Err(TreeError::Outside { .. })
    ));
}

/// The hole a "may not exist" resolver invites: a name that already exists
/// is not the absent case at all, and assembling it by hand instead of
/// checking it hands back a symlink's target unexamined.
#[cfg(unix)]
#[test]
fn a_name_that_already_exists_as_a_symlink_out_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("tempdir");
    std::fs::write(outside.path().join("secret"), "x").expect("write");
    std::os::unix::fs::symlink(outside.path().join("secret"), dir.path().join("link"))
        .expect("symlink");

    assert!(matches!(
        resolve_new(dir.path(), "link"),
        Err(TreeError::Outside { .. })
    ));
}

/// The easier attack of the two: `exists()` follows a symlink and answers
/// about its *target*, so a link pointing at nothing reads as "not there" and
/// would fall through to the parent-only answer unexamined. `symlink_metadata`
/// is what tells the two apart.
#[cfg(unix)]
#[test]
fn a_broken_symlink_is_refused_rather_than_treated_as_absent() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::os::unix::fs::symlink(dir.path().join("never-written"), dir.path().join("link"))
        .expect("symlink");

    // Refused because `resolve` cannot canonicalise it, not because it climbs
    // out — the name is taken by something this cannot vouch for either way.
    assert!(matches!(
        resolve_new(dir.path(), "link"),
        Err(TreeError::Unreadable { .. })
    ));
}

/// `.git` is the repository's own database, not a file the tree hands out a
/// writable path to — wherever it sits in the path, not only at the end.
#[test]
fn a_dot_git_segment_is_refused_wherever_it_sits() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("a")).expect("create");

    for path in [".git", ".git/config", "a/.git/b"] {
        assert!(
            matches!(
                resolve_new(dir.path(), path),
                Err(TreeError::Outside { .. })
            ),
            "{path} was allowed through"
        );
    }
}

/// The rule itself, called directly rather than only through `resolve_new`.
#[test]
fn touches_git_is_true_for_a_dot_git_segment_anywhere() {
    assert!(touches_git(".git"));
    assert!(touches_git(".git/config"));
    assert!(touches_git("a/.git/b"));
    assert!(!touches_git("a/gitignore"));
    assert!(!touches_git("a/b"));
}
