use super::*;

/// The sandbox this machine has: bwrap, else docker with the image
/// `DEVFLOW_SANDBOX_IMAGE` names, already pulled.
fn here() -> Option<Sandbox> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let image = std::env::var("DEVFLOW_SANDBOX_IMAGE").ok();
    match found(SandboxChoice::Auto, image.as_deref(), &path) {
        Ok(sandbox) => Some(sandbox),
        Err(why) => {
            eprintln!("not run here: {why}");
            None
        }
    }
}

fn git(repo: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .args(args)
        .current_dir(repo)
        .status()
        .is_ok_and(|status| status.success());
    assert!(ok, "git {args:?}");
}

fn repo() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().join("checkout");
    std::fs::create_dir_all(root.join("node_modules/lib")).expect("deps");
    git(&root, &["init", "-q"]);
    git(&root, &["config", "user.email", "test@example.invalid"]);
    git(&root, &["config", "user.name", "Test"]);
    git(&root, &["config", "commit.gpgsign", "false"]);
    std::fs::write(root.join("app.sh"), "echo app\n").expect("app");
    std::fs::write(root.join(".gitignore"), "node_modules/\n").expect("ignore");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "first"]);
    (dir, root)
}

#[test]
fn a_sandbox_is_asked_for_by_name_or_found_and_says_why_not() {
    let empty = std::ffi::OsString::new();
    assert!(found(SandboxChoice::Off, None, &empty)
        .expect_err("off")
        .contains("off"));
    assert!(found(SandboxChoice::Docker, None, &empty)
        .expect_err("no image")
        .contains("stages.attack.image"));
    let none = found(SandboxChoice::Auto, Some("node:22"), &empty).expect_err("nothing here");
    assert!(none.starts_with("no sandbox here"), "{none}");
}

#[test]
fn the_sandbox_has_no_network_a_read_only_root_and_limits() {
    let limits = Limits {
        time: Duration::from_secs(60),
        memory_mb: 512,
        cpus: 2,
    };
    let bwrap = Sandbox {
        kind: Kind::Bwrap,
        program: "/usr/bin/bwrap".into(),
        image: None,
        prlimit: Some("/usr/bin/prlimit".into()),
        network: None,
        env: Vec::new(),
    };
    let seen = Seen {
        deps: vec![PathBuf::from("/home/u/shop/node_modules")],
        home: Some(PathBuf::from("/home/u")),
        tools: vec![PathBuf::from("/home/u/.nvm/versions/node/v22")],
    };
    let tree = Path::new("/home/u/.cache/t1");
    let said = argv(&bwrap, tree, &seen, "npx jest", limits, "n").join(" ");
    for part in [
        "--tmpfs /run",
        "--tmpfs /home/u",
        "--ro-bind /home/u/shop/node_modules /home/u/shop/node_modules",
        "--ro-bind /home/u/.nvm/versions/node/v22 /home/u/.nvm/versions/node/v22",
        "--bind /home/u/.cache/t1 /home/u/.cache/t1",
    ] {
        assert!(said.contains(part), "{part}: {said}");
    }
    let at = |part: &str| said.find(part).expect(part);
    assert!(
        at("--tmpfs /home/u") < at("--bind /home/u/.cache/t1"),
        "the home hidden, then the tree shown"
    );
    for part in [
        "--unshare-net",
        "--ro-bind / /",
        "--cpu=120",
        "--data=536870912",
        "sh -c npx jest",
    ] {
        assert!(said.contains(part), "{part}: {said}");
    }
    let docker = Sandbox {
        kind: Kind::Docker,
        program: "/usr/bin/docker".into(),
        image: Some("node:22".into()),
        prlimit: None,
        network: None,
        env: Vec::new(),
    };
    let seen = Seen {
        deps: vec![PathBuf::from("/c/node_modules")],
        ..Seen::default()
    };
    let said = argv(
        &docker,
        Path::new("/w/tree"),
        &seen,
        "npx jest",
        limits,
        "n",
    )
    .join(" ");
    assert!(said.contains("--user "), "{said}");
    for part in [
        "--network none",
        "--read-only",
        "--memory 512m",
        "--cpus 2",
        "--cap-drop ALL",
        "-v /c/node_modules:/c/node_modules:ro",
        "node:22 sh -c npx jest",
    ] {
        assert!(said.contains(part), "{part}: {said}");
    }
}

#[test]
fn an_exploit_is_placed_only_inside_its_worktree() {
    let dir = tempfile::tempdir().expect("dir");
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).expect("tree");
    assert!(place(&tree, "tests/a.test.sh", "exit 1").is_ok());
    assert!(place(&tree, "../a.test.sh", "x").is_err());
    assert!(
        place(&tree, ".git/hooks/pre-commit", "x").is_err(),
        "never a hook"
    );
    let again = place(&tree, "tests/a.test.sh", "x").expect_err("the project's own file");
    assert!(again.contains("new file"), "{again}");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(dir.path(), tree.join("out")).expect("link");
        assert!(
            place(&tree, "out/a.test.sh", "x").is_err(),
            "a link out of it"
        );
        assert!(place(&tree, "out/deeper/a.test.sh", "x").is_err());
        assert!(!dir.path().join("deeper").exists(), "nothing made outside");
    }
}

#[cfg(unix)]
#[test]
fn an_exploit_runs_red_or_green_in_a_throwaway_worktree_and_reaches_no_network() {
    let Some(sandbox) = here() else {
        return;
    };
    let (dir, root) = repo();
    let head = crate::git::head_of(&root).expect("head");
    let at = dir.path().join("trees/t1");
    let limits = Limits {
        time: Duration::from_secs(60),
        ..Limits::default()
    };
    {
        let tree = tree_at(&root, &head, &at).expect("tree");
        assert!(tree.at.join("node_modules").is_symlink(), "deps linked in");
        place(&tree.at, "tests/red.sh", "exit 1").expect("placed");
        let red = run(
            &sandbox,
            &tree,
            "sh \"$DEVFLOW_EXPLOIT\"",
            ("tests/red.sh", "red"),
            limits,
        );
        assert_eq!(red.outcome, Outcome::Red, "{red:?}");
        place(&tree.at, "tests/green.sh", "exit 0").expect("placed");
        let green = run(
            &sandbox,
            &tree,
            "sh \"$DEVFLOW_EXPLOIT\"",
            ("tests/green.sh", "green"),
            limits,
        );
        assert_eq!(green.outcome, Outcome::Green, "{green:?}");
        // A public host and the metadata service are out of reach.
        let reach = "for url in http://1.1.1.1/ http://169.254.169.254/latest/meta-data/; do if command -v wget >/dev/null; then wget -q -T 3 -O /dev/null $url && exit 0; elif command -v curl >/dev/null; then curl -s -m 3 -o /dev/null $url && exit 0; fi; done; exit 7";
        let none = run(&sandbox, &tree, reach, ("x", "x"), limits);
        assert_eq!(none.exit, Some(7), "{none:?}");
        // The throwaway copy is the one place a test writes.
        let writes = run(
            &sandbox,
            &tree,
            "echo ok > written.txt && test -s written.txt",
            ("x", "x"),
            limits,
        );
        assert_eq!(writes.outcome, Outcome::Green, "{writes:?}");
        // So is the checkout: whatever the test writes, it is not there.
        let write = format!("echo x > '{}/app.sh'", root.display());
        run(&sandbox, &tree, &write, ("x", "x"), limits);
        assert_eq!(
            std::fs::read_to_string(root.join("app.sh")).expect("app"),
            "echo app\n"
        );
        let slow = run(
            &sandbox,
            &tree,
            "sleep 20",
            ("x", "x"),
            Limits {
                time: Duration::from_secs(2),
                ..limits
            },
        );
        assert_eq!(slow.outcome, Outcome::TimedOut);
    }
    assert!(!at.exists(), "the worktree is gone");
}

#[test]
fn the_toolchains_under_home_are_shown_and_its_secrets_are_not() {
    let dir = tempfile::tempdir().expect("dir");
    let home = dir.path();
    for folder in [
        ".cargo/bin",
        ".cargo/registry",
        ".rustup",
        ".nvm/versions/node/v22/bin",
        ".nvm/versions/node/v22/lib",
        ".local/bin",
        ".local/share/keyrings",
    ] {
        std::fs::create_dir_all(home.join(folder)).expect("folder");
    }
    let path = std::env::join_paths([
        home.join(".cargo/bin"),
        home.join(".nvm/versions/node/v22/bin"),
        home.join(".local/bin"),
        PathBuf::from("/usr/bin"),
    ])
    .expect("path");
    let shown = tools(home, &path);
    for want in [
        ".cargo/bin",
        ".cargo/registry",
        ".rustup",
        ".nvm/versions/node/v22",
        ".local/bin",
    ] {
        assert!(shown.contains(&home.join(want)), "{want}: {shown:?}");
    }
    for never in [".cargo", ".local", ".local/share/keyrings", ""] {
        assert!(!shown.contains(&home.join(never)), "{never}: {shown:?}");
    }
}

#[test]
fn a_throwaway_worktree_is_removed_when_its_run_fails() {
    let (dir, root) = repo();
    let head = crate::git::head_of(&root).expect("head");
    let at = dir.path().join("trees/failed");
    let failed = (|| -> Result<(), String> {
        let tree = tree_at(&root, &head, &at)?;
        place(&tree.at, ".git/hooks/pre-commit", "x")?;
        Ok(())
    })();
    assert!(failed.is_err());
    assert!(!at.exists(), "gone even when the run failed");
    assert!(
        crate::git::worktrees(&root)
            .expect("worktrees")
            .iter()
            .all(|tree| !tree.contains("failed")),
        "git forgets it too"
    );
}

#[test]
fn a_stacks_exploit_joins_its_network_and_is_told_its_targets() {
    let docker = Sandbox {
        kind: Kind::Docker,
        program: PathBuf::from("/usr/bin/docker"),
        image: Some("alpine".to_owned()),
        prlimit: None,
        network: Some("devflow-stack-1-net".to_owned()),
        env: vec![(
            "DEVFLOW_SECURITY_TARGETS".to_owned(),
            "http://web:8080".to_owned(),
        )],
    };
    let seen = Seen::default();
    let argv = argv(
        &docker,
        Path::new("/tree"),
        &seen,
        "true",
        Limits::default(),
        "n",
    );
    let at = argv
        .iter()
        .position(|one| one == "--network")
        .expect("network");
    assert_eq!(argv[at + 1], "devflow-stack-1-net");
    assert!(argv.contains(&"DEVFLOW_SECURITY_TARGETS=http://web:8080".to_owned()));
}

#[test]
fn a_tree_of_a_detached_review_tree_gets_the_main_checkouts_dependencies() {
    let (dir, root) = repo();
    let head = crate::git::head_of(&root).expect("head");
    // The tree an attack on a range reviews in: a worktree with no
    // node_modules of its own.
    let review = dir.path().join("review");
    crate::git::add_detached(&root, &review, &head).expect("review tree");
    assert!(dependencies(&review).is_empty());
    let deps = dependencies_for(&review);
    assert_eq!(deps.len(), 1, "{deps:?}");
    assert_eq!(
        deps[0].canonicalize().unwrap(),
        root.join("node_modules").canonicalize().unwrap()
    );
    let at = dir.path().join("exploit-tree");
    let tree = tree_at(&review, &head, &at).expect("tree");
    assert!(at.join("node_modules/lib").is_dir(), "linked in");
    assert_eq!(tree.deps.len(), 1);
    drop(tree);
    crate::git::remove_detached(&root, &review);
}
