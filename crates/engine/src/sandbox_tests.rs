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
        deps: vec![Mount {
            from: PathBuf::from("/home/u/shop/node_modules"),
            to: PathBuf::from("/home/u/.cache/t1/node_modules"),
        }],
        home: Some(PathBuf::from("/home/u")),
        tools: vec![PathBuf::from("/home/u/.nvm/versions/node/v22")],
        caches: vec![Mount {
            from: PathBuf::from("/home/u/.cargo/registry"),
            to: PathBuf::from("/tmp/devflow-cargo/registry"),
        }],
        writable: vec![PathBuf::from("/tmp/devflow-cargo")],
        env: vec![("CARGO_HOME".to_owned(), "/tmp/devflow-cargo".to_owned())],
        prelude: Some("export A=1\n".to_owned()),
    };
    let tree = Path::new("/home/u/.cache/t1");
    let said = argv(&bwrap, tree, &seen, "npx jest", limits, "n").join(" ");
    for part in [
        "--tmpfs /run",
        "--tmpfs /home/u",
        "--ro-bind /home/u/shop/node_modules /home/u/.cache/t1/node_modules",
        "--ro-bind /home/u/.nvm/versions/node/v22 /home/u/.nvm/versions/node/v22",
        "--bind /home/u/.cache/t1 /home/u/.cache/t1",
        "--ro-bind /home/u/.cargo/registry /tmp/devflow-cargo/registry",
        "--setenv CARGO_HOME /tmp/devflow-cargo",
    ] {
        assert!(said.contains(part), "{part}: {said}");
    }
    let at = |part: &str| said.find(part).expect(part);
    assert!(
        at("--tmpfs /home/u") < at("--bind /home/u/.cache/t1"),
        "the home hidden, then the tree shown"
    );
    assert!(
        at("--bind /home/u/.cache/t1") < at("--ro-bind /home/u/shop/node_modules"),
        "the tree, then its dependencies over it"
    );
    assert!(said.ends_with("sh -c export A=1\nnpx jest"), "{said}");
    assert!(
        at("--tmpfs /tmp/devflow-cargo") < at("--ro-bind /home/u/.cargo/registry"),
        "a toolchain's home made writable, then its cache mounted in it"
    );
    for part in [
        "--unshare-net",
        "--ro-bind / /",
        "--cpu=120",
        "--data=536870912",
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
        deps: vec![Mount {
            from: PathBuf::from("/c/node_modules"),
            to: PathBuf::from("/w/tree/node_modules"),
        }],
        caches: vec![Mount {
            from: PathBuf::from("/c/go/pkg/mod"),
            to: PathBuf::from("/tmp/devflow-go/mod"),
        }],
        writable: vec![PathBuf::from("/tmp/devflow-go")],
        env: vec![("GOPROXY".to_owned(), "off".to_owned())],
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
        "-v /c/node_modules:/w/tree/node_modules:ro",
        "-v /c/go/pkg/mod:/tmp/devflow-go/mod:ro",
        "--tmpfs /tmp/devflow-go:exec,mode=1777",
        "-e GOPROXY=off",
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
        assert!(
            tree.at.join("node_modules").is_dir(),
            "a place to mount deps"
        );
        assert_eq!(tree.deps[0].to, tree.at.join("node_modules"));
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
        ".rustup",
        ".nvm/versions/node/v22",
        ".local/bin",
    ] {
        assert!(shown.contains(&home.join(want)), "{want}: {shown:?}");
    }
    // The registry is a Rust project's alone, seen as its CARGO_HOME.
    for never in [
        ".cargo",
        ".cargo/registry",
        ".local",
        ".local/share/keyrings",
        "",
    ] {
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
    assert_eq!(tree.deps.len(), 1);
    assert_eq!(tree.deps[0].to, at.join("node_modules"));
    assert_eq!(
        tree.deps[0].from.canonicalize().unwrap(),
        root.join("node_modules").canonicalize().unwrap()
    );
    drop(tree);
    crate::git::remove_detached(&root, &review);
}

#[test]
fn a_test_named_before_the_end_of_a_long_red_run_is_still_reached() {
    let name = "forged sessions \u{203a} accepts a cookie signed with any key";
    let said = format!(
        "FAIL tests/session.exploit.test.ts\n  \u{25cf} {name}\n\n    Expected: false\n{}\nTests: 2 failed, 2 total\n",
        "      at Object.<anonymous> (tests/session.exploit.test.ts:9:26)\n".repeat(100)
    );
    let (tail, reached, _, _) = judged(
        &said,
        "forged sessions accepts a cookie signed with any key",
        false,
    );
    assert!(
        !tail.contains("accepts a cookie"),
        "the end alone does not name it"
    );
    assert!(reached);
}

/// A tree of nothing but `files`, for what a language needs.
fn tree_of(dir: &Path, files: &[&str]) -> Tree {
    let at = dir.join("tree");
    std::fs::create_dir_all(&at).expect("tree");
    for file in files {
        std::fs::write(at.join(file), "").expect("file");
    }
    Tree {
        root: dir.join("checkout"),
        at,
        deps: Vec::new(),
        warm: None,
    }
}

#[test]
fn a_rust_run_starts_from_its_attacks_warm_build_read_only() {
    let dir = tempfile::tempdir().expect("dir");
    let warm = dir.path().join("warm/target");
    std::fs::create_dir_all(&warm).expect("warm");
    let mut tree = tree_of(dir.path(), &["Cargo.toml"]);
    let mut none = Language::default();
    from_warm(&mut none, &tree);
    assert_eq!(none, Language::default(), "no warm build, nothing changes");
    tree.warm = Some(warm.clone());
    let mut rust = Language::default();
    from_warm(&mut rust, &tree);
    assert_eq!(
        rust.caches,
        [Mount {
            from: warm.clone(),
            to: PathBuf::from(CARGO_WARM)
        }]
    );
    let prelude = rust.prelude.expect("a prelude");
    assert!(
        prelude.contains("cp -a /tmp/devflow-cargo-warm/. target/")
            && prelude.contains("|| rm -rf target"),
        "{prelude}"
    );
    let seen = Seen {
        caches: rust.caches.clone(),
        ..Seen::default()
    };
    let docker = Sandbox {
        kind: Kind::Docker,
        program: "/usr/bin/docker".into(),
        image: Some("rust:1".into()),
        prlimit: None,
        network: None,
        env: Vec::new(),
    };
    let argv = argv(
        &docker,
        &tree.at,
        &seen,
        "cargo test",
        Limits::default(),
        "n",
    );
    assert!(
        argv.contains(&format!("{}:{CARGO_WARM}:ro", warm.display())),
        "{argv:?}"
    );
    std::fs::remove_file(tree.at.join("Cargo.toml")).expect("not rust");
    let mut other = Language::default();
    from_warm(&mut other, &tree);
    assert_eq!(other, Language::default(), "only a Rust project");
}

#[test]
fn rust_sees_its_registry_and_go_its_modules_read_only_and_offline() {
    let dir = tempfile::tempdir().expect("dir");
    let home = dir.path().join("home");
    for folder in [".cargo/registry", ".cargo/git", "go/pkg/mod", ".rustup"] {
        std::fs::create_dir_all(home.join(folder)).expect("folder");
    }
    std::fs::write(home.join(".cargo/credentials.toml"), "token").expect("secret");
    let none = |_: &str| None;
    let empty = std::ffi::OsString::new();
    let rust = tree_of(dir.path(), &["Cargo.toml"]);
    let said = language_with(&rust, Kind::Docker, Some(&home), &empty, &none);
    assert_eq!(
        said.caches,
        vec![
            Mount {
                from: home.join(".cargo/registry"),
                to: PathBuf::from("/tmp/devflow-cargo/registry"),
            },
            Mount {
                from: home.join(".cargo/git"),
                to: PathBuf::from("/tmp/devflow-cargo/git"),
            },
        ],
        "never the credentials"
    );
    let env = |said: &Language, name: &str| {
        said.env
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    assert_eq!(env(&said, "CARGO_HOME").as_deref(), Some(CARGO_HOME));
    assert_eq!(env(&said, "CARGO_NET_OFFLINE").as_deref(), Some("true"));
    assert_eq!(env(&said, "RUSTUP_HOME"), None, "docker brings its own");
    let bwrap = language_with(&rust, Kind::Bwrap, Some(&home), &empty, &none);
    assert_eq!(
        env(&bwrap, "RUSTUP_HOME"),
        Some(home.join(".rustup").display().to_string())
    );
    let other = tempfile::tempdir().expect("dir");
    let go = tree_of(other.path(), &["go.mod"]);
    let said = language_with(&go, Kind::Docker, Some(&home), &empty, &none);
    assert_eq!(
        said.caches,
        vec![Mount {
            from: home.join("go/pkg/mod"),
            to: PathBuf::from("/tmp/devflow-go/mod"),
        }]
    );
    for (name, value) in [
        ("GOPROXY", "off"),
        ("GOTOOLCHAIN", "local"),
        ("GOMODCACHE", "/tmp/devflow-go/mod"),
    ] {
        assert_eq!(env(&said, name).as_deref(), Some(value), "{name}");
    }
    let node = tempfile::tempdir().expect("dir");
    let node = tree_of(node.path(), &["package.json"]);
    assert_eq!(
        language_with(&node, Kind::Docker, Some(&home), &empty, &none),
        Language::default(),
        "a project sees no other language's caches"
    );
}

/// A venv as `python -m venv` leaves it, for `version`, with an editable
/// install of the project at `root`.
fn venv_at(at: &Path, version: &str, base: &str, root: &Path) -> PathBuf {
    let site = at.join("lib").join(version).join("site-packages");
    std::fs::create_dir_all(&site).expect("site");
    std::fs::write(
        at.join("pyvenv.cfg"),
        format!("home = {base}\ninclude-system-site-packages = false\n"),
    )
    .expect("cfg");
    std::fs::write(
        site.join("__editable__.shop-1.0.pth"),
        format!("{}\n", root.join("src").display()),
    )
    .expect("pth");
    std::fs::write(site.join("distutils-precedence.pth"), "import os\n").expect("pth");
    site
}

/// An editable install the way setuptools makes one for a layout a path
/// cannot hold: a `.pth` that imports a finder, whose `MAPPING` leads the
/// package `name` to `folder`.
fn finder_at(site: &Path, name: &str, folder: &Path) {
    let module = format!("__editable___{name}_1_0_finder");
    std::fs::write(
        site.join(format!("{module}.py")),
        format!(
            "import sys\n\
             from importlib.util import spec_from_file_location\n\
             from pathlib import Path\n\
             MAPPING: dict[str, str] = {{'{name}': '{}'}}\n\
             NAMESPACES: dict[str, list[str]] = {{}}\n\
             class _EditableFinder:\n\
             \x20   @classmethod\n\
             \x20   def find_spec(cls, fullname, path=None, target=None):\n\
             \x20       if fullname not in MAPPING:\n\
             \x20           return None\n\
             \x20       at = Path(MAPPING[fullname])\n\
             \x20       return spec_from_file_location(fullname, at / '__init__.py', submodule_search_locations=[str(at)])\n\
             def install():\n\
             \x20   if not any(finder == _EditableFinder for finder in sys.meta_path):\n\
             \x20       sys.meta_path.append(_EditableFinder)\n",
            folder.display()
        ),
    )
    .expect("finder");
    std::fs::write(
        site.join(format!("__editable__.{name}-1.0.pth")),
        format!("import {module}; {module}.install()\n"),
    )
    .expect("pth");
}

#[test]
fn an_editable_finder_is_said_again_of_the_worktree_and_nothing_else_is_read() {
    let dir = tempfile::tempdir().expect("dir");
    let checkout = dir.path().join("checkout");
    let venv = checkout.join(".venv");
    let site = venv_at(&venv, "python3.12", "/usr/bin", &checkout);
    finder_at(&site, "vault", &checkout.join("lib/vault"));
    // A module a `.pth` imports that names no checkout path is left alone,
    // as is one past a link or not a module's plain name.
    std::fs::write(site.join("other.pth"), "import plain, ../evil; import os\n").expect("pth");
    std::fs::write(site.join("plain.py"), "X = '/usr/lib'\n").expect("module");
    let tree = dir.path().join("tree");
    let said = editable(&venv, "python3.12", std::slice::from_ref(&checkout), &tree);
    assert_eq!(said.paths, [tree.join("src").display().to_string()]);
    assert_eq!(said.modules.len(), 1, "{said:?}");
    let (name, text) = &said.modules[0];
    assert_eq!(name, "__editable___vault_1_0_finder");
    assert!(
        text.contains(&format!(
            "{{'vault': '{}'}}",
            tree.join("lib/vault").display()
        )),
        "{text}"
    );
    assert!(!text.contains(&checkout.display().to_string()), "{text}");
    let prelude = python_prelude(
        Path::new("/tmp/made"),
        &tree.join(".venv"),
        "python3.12",
        None,
        &said,
    );
    assert!(
        prelude.contains(
            "> '/tmp/made'/lib/python3.12/site-packages/__editable___vault_1_0_finder.py"
        ),
        "{prelude}"
    );
    assert_eq!(
        imported("import a, b as c; x = 1; import d"),
        ["a", "b", "d"]
    );
    assert!(imported("import ../x").is_empty());
}

#[test]
fn a_checkout_inside_another_root_is_said_again_by_the_deepest() {
    let dir = tempfile::tempdir().expect("dir");
    let main = dir.path().join("main");
    let checkout = main.join("wt");
    let venv = checkout.join(".venv");
    let site = venv_at(&venv, "python3.12", "/usr/bin", &checkout);
    finder_at(&site, "a", &checkout.join("lib/a"));
    let tree = dir.path().join("tree");
    let said = editable(&venv, "python3.12", &[main, checkout], &tree);
    assert_eq!(said.paths, [tree.join("src").display().to_string()]);
    assert!(
        said.modules[0]
            .1
            .contains(&format!("'{}'", tree.join("lib/a").display())),
        "{said:?}"
    );
}

#[test]
fn the_modules_said_again_stay_within_one_argument() {
    let dir = tempfile::tempdir().expect("dir");
    let checkout = dir.path().join("checkout");
    let venv = checkout.join(".venv");
    let site = venv_at(&venv, "python3.12", "/usr/bin", &checkout);
    let padding = "#".repeat(30 * 1024);
    for name in ["a", "b", "c"] {
        finder_at(&site, name, &checkout.join(name));
        let module = site.join(format!("__editable___{name}_1_0_finder.py"));
        let text = std::fs::read_to_string(&module).expect("finder");
        std::fs::write(&module, format!("{text}{padding}\n")).expect("padded");
    }
    let said = editable(&venv, "python3.12", &[checkout], &dir.path().join("tree"));
    let held: usize = said.modules.iter().map(|(_, text)| text.len()).sum();
    assert_eq!(said.modules.len(), 2, "two fit, the third would not");
    assert!(held <= MOST_MODULES_TEXT, "{held}");
}

#[test]
fn a_python_venv_is_made_the_one_python_runs_with_the_worktrees_own_code() {
    let dir = tempfile::tempdir().expect("dir");
    let checkout = dir.path().join("checkout");
    let venv = checkout.join(".venv");
    venv_at(&venv, "python3.12", "/usr/bin", &checkout);
    let mut tree = tree_of(dir.path(), &["pyproject.toml"]);
    tree.root = checkout.clone();
    tree.deps.push(Mount {
        from: venv.clone(),
        to: tree.at.join(".venv"),
    });
    let empty = std::ffi::OsString::new();
    let said = language_with(&tree, Kind::Docker, None, &empty, &|_: &str| None);
    let prelude = said.prelude.clone().expect("a prelude");
    for part in [
        "command -v python3.12",
        "'/usr/bin/python3.12'",
        &format!(
            "site.addsitedir(\"{}\")",
            tree.at.join(".venv/lib/python3.12/site-packages").display()
        ),
        &format!("'{}'", tree.at.join("src").display()),
        "export PATH VIRTUAL_ENV",
    ] {
        assert!(prelude.contains(part), "{part}: {prelude}");
    }
    assert!(
        !prelude.contains(&format!("'{}'", checkout.join("src").display())),
        "never the checkout's code: {prelude}"
    );
    assert_eq!(
        unwrapped("uv run python -m pytest \"$DEVFLOW_EXPLOIT\"", &said),
        "python -m pytest \"$DEVFLOW_EXPLOIT\""
    );
    assert_eq!(
        unwrapped("uv run python -m pytest", &Language::default()),
        "uv run python -m pytest",
        "only once the venv is made"
    );
}

#[cfg(unix)]
#[test]
fn the_venv_made_runs_the_projects_packages_and_the_worktrees_code() {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let Some(python) = crate::env::found_on(&path, OsStr::new("python3")) else {
        return;
    };
    let version = Command::new(&python)
        .args([
            "-c",
            "import sys; print(f'python{sys.version_info[0]}.{sys.version_info[1]}')",
        ])
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .unwrap_or_default();
    let dir = tempfile::tempdir().expect("dir");
    let checkout = dir.path().join("checkout");
    let venv = checkout.join(".venv");
    let base = python.parent().expect("bin").display().to_string();
    let site = venv_at(&venv, &version, &base, &checkout);
    std::fs::write(site.join("shoplib.py"), "WHO = 'the venv'\n").expect("package");
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(tree.join("src")).expect("src");
    std::fs::write(tree.join("src/shop.py"), "WHO = 'the worktree'\n").expect("code");
    std::fs::create_dir_all(checkout.join("src")).expect("src");
    std::fs::write(checkout.join("src/shop.py"), "WHO = 'the checkout'\n").expect("code");
    // setuptools' finder: `lib` is on no path, only its MAPPING leads there.
    finder_at(&site, "vault", &checkout.join("lib/vault"));
    for (root, who) in [(&tree, "the worktree"), (&checkout, "the checkout")] {
        std::fs::create_dir_all(root.join("lib/vault")).expect("lib");
        std::fs::write(
            root.join("lib/vault/__init__.py"),
            format!("WHO = '{who}'\n"),
        )
        .expect("package");
    }
    let made = dir.path().join("made");
    let roots = [checkout.clone()];
    let prelude = python_prelude(
        &made,
        &venv,
        &version,
        Some(python.parent().expect("bin")),
        &editable(&venv, &version, &roots, &tree),
    );
    let said = Command::new("sh")
        .args([
            "-c",
            &format!(
                "{prelude}python -c 'import shoplib, shop, vault, sys; print(shoplib.WHO, \"/\", shop.WHO, \"/\", vault.WHO, \"/\", sys.prefix)'"
            ),
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .expect("sh");
    let out = String::from_utf8_lossy(&said.stdout);
    assert!(
        out.contains("the venv / the worktree / the worktree"),
        "{out} {}",
        String::from_utf8_lossy(&said.stderr)
    );
    assert!(out.contains(&made.display().to_string()), "{out}");
}

#[test]
fn under_bwrap_a_venvs_python_under_the_home_is_shown_but_never_local_whole() {
    let dir = tempfile::tempdir().expect("dir");
    let home = dir.path().join("home");
    let uv = home.join(".local/share/uv/python/cpython-3.12/bin");
    std::fs::create_dir_all(&uv).expect("uv");
    std::fs::create_dir_all(home.join(".local/share/uv/python/cpython-3.12/lib/python3.12"))
        .expect("stdlib");
    std::fs::create_dir_all(home.join(".local/lib/python3.12")).expect("user site");
    let empty = std::ffi::OsString::new();
    for (base, shown) in [
        (
            uv.clone(),
            Some(home.join(".local/share/uv/python/cpython-3.12")),
        ),
        (home.join(".local/bin"), None),
    ] {
        let checkout = dir.path().join("checkout");
        let venv = checkout.join(".venv");
        let _ = std::fs::remove_dir_all(&venv);
        venv_at(&venv, "python3.12", &base.display().to_string(), &checkout);
        let mut tree = tree_of(dir.path(), &["pyproject.toml"]);
        tree.deps.push(Mount {
            from: venv,
            to: tree.at.join(".venv"),
        });
        let said = language_with(&tree, Kind::Bwrap, Some(&home), &empty, &|_: &str| None);
        assert_eq!(
            said.tools,
            shown.into_iter().collect::<Vec<_>>(),
            "{base:?}"
        );
    }
}
