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

/// A repository with one commit and a linked worktree of it: both roots.
#[cfg(unix)]
fn repository_with_a_worktree(dir: &Path) -> (PathBuf, PathBuf) {
    let git = |at: &Path, args: &[&str]| {
        let done = std::process::Command::new("git")
            .args(args)
            .current_dir(at)
            .output()
            .expect("git");
        assert!(done.status.success(), "git {args:?}");
    };
    let main = dir.join("main");
    std::fs::create_dir_all(main.join(".devpit/devflow")).expect("main");
    git(&main, &["init", "-q"]);
    git(&main, &["config", "user.email", "test@example.invalid"]);
    git(&main, &["config", "user.name", "Test"]);
    git(&main, &["config", "commit.gpgsign", "false"]);
    std::fs::write(main.join(".gitignore"), ".devpit/\n").expect("ignore");
    std::fs::write(main.join("secret.env"), "KEY=1\n").expect("file");
    git(&main, &["add", ".gitignore"]);
    git(&main, &["commit", "-q", "-m", "first"]);
    std::fs::write(main.join(".devpit/devflow/devflow.yaml"), "version: 2\n").expect("yaml");
    let worktree = dir.join("wt");
    git(
        &main,
        &[
            "worktree",
            "add",
            "-q",
            worktree.to_str().expect("utf-8"),
            "-b",
            "wt",
        ],
    );
    (
        main.canonicalize().expect("main"),
        worktree.canonicalize().expect("worktree"),
    )
}

/// A linked worktree knows its repository's main checkout, from what git
/// wrote there; the main checkout itself has none.
#[cfg(unix)]
#[test]
fn a_linked_worktree_knows_its_main_checkout() {
    let dir = tempfile::tempdir().expect("dir");
    let (main, worktree) = repository_with_a_worktree(dir.path());
    assert_eq!(main_checkout(&worktree), Some(main.clone()));
    assert_eq!(main_checkout(&main), None);
    assert_eq!(main_checkout(dir.path()), None);
}

/// A worktree's devflow folder linked to the same folder of its main
/// checkout is read through, and said as the worktree's own; any other
/// link out of the worktree is refused, the main checkout's other files
/// included.
#[cfg(unix)]
#[test]
fn a_worktrees_devflow_folder_may_be_its_main_checkouts() {
    let dir = tempfile::tempdir().expect("dir");
    let (main, worktree) = repository_with_a_worktree(dir.path());
    std::os::unix::fs::symlink(main.join(".devpit"), worktree.join(".devpit")).expect("link");
    let yaml = resolve(&worktree, ".devpit/devflow/devflow.yaml").expect("read through");
    assert_eq!(yaml, main.join(".devpit/devflow/devflow.yaml"));
    assert_eq!(
        relative_to(&worktree, &yaml).expect("its own"),
        ".devpit/devflow/devflow.yaml"
    );
    assert!(resolve_new(&worktree, ".devpit/devflow/runs").is_ok());
    // Climbing out of the shared folder is refused.
    assert!(resolve(&worktree, ".devpit/../.devpit/../secret.env").is_err());
    std::os::unix::fs::symlink(main.join("secret.env"), worktree.join("secret.env")).expect("link");
    assert!(
        resolve(&worktree, "secret.env").is_err(),
        "not a devflow folder"
    );
    std::os::unix::fs::symlink(main.join(".devpit"), worktree.join("devpit-too")).expect("link");
    assert!(resolve(&worktree, "devpit-too/devflow/devflow.yaml").is_err());
}

/// The main checkout's devflow folder that is itself a link out (the
/// repository's own `.devpit -> /`) is no folder of the main checkout's: a
/// worktree linking to it is refused as the main checkout refuses it.
#[cfg(unix)]
#[test]
fn a_main_checkouts_devflow_folder_linked_out_shares_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let (main, worktree) = repository_with_a_worktree(dir.path());
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&outside).expect("outside");
    std::fs::write(outside.join("secret"), "KEY=1\n").expect("secret");
    std::os::unix::fs::symlink(&outside, main.join(".devflow")).expect("link out");
    std::os::unix::fs::symlink(main.join(".devflow"), worktree.join(".devflow")).expect("link");
    assert!(
        resolve(&main, ".devflow/secret").is_err(),
        "the main refuses it"
    );
    assert!(
        resolve(&worktree, ".devflow/secret").is_err(),
        "so does the worktree"
    );
    assert!(resolve_new(&worktree, ".devflow/written").is_err());
    std::os::unix::fs::symlink("/", worktree.join(".devpit-root")).expect("link");
    assert!(resolve(&worktree, ".devpit-root/etc/hostname").is_err());
}

/// `.devflow` and `.devpit/devflow` may each be the link, said as the
/// worktree's own; a `.git` file written in a folder that is no worktree of
/// the repository names no main checkout.
#[cfg(unix)]
#[test]
fn each_devflow_folder_may_be_shared_and_a_forged_git_file_names_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let (main, worktree) = repository_with_a_worktree(dir.path());
    std::fs::create_dir_all(main.join(".devflow")).expect("folder");
    std::fs::write(main.join(".devflow/devflow.yaml"), "version: 2\n").expect("yaml");
    std::os::unix::fs::symlink(main.join(".devflow"), worktree.join(".devflow")).expect("link");
    assert!(resolve(&worktree, ".devflow/devflow.yaml").is_ok());
    std::fs::create_dir_all(worktree.join(".devpit")).expect("folder");
    std::os::unix::fs::symlink(
        main.join(".devpit/devflow"),
        worktree.join(".devpit/devflow"),
    )
    .expect("link");
    let yaml = resolve(&worktree, ".devpit/devflow/devflow.yaml").expect("read through");
    assert_eq!(
        relative_to(&worktree, &yaml).expect("its own"),
        ".devpit/devflow/devflow.yaml"
    );
    let forged = dir.path().join("forged");
    std::fs::create_dir_all(&forged).expect("folder");
    std::fs::write(
        forged.join(".git"),
        format!("gitdir: {}\n", main.join(".git/worktrees/wt").display()),
    )
    .expect("forged");
    assert_eq!(main_checkout(&forged), None);
}
