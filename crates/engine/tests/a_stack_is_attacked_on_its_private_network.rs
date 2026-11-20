//! A stack the attack starts: on an internal network, reached by the
//! exploits attached to it, taken down whatever happened. These start real
//! containers, so they run only where `DEVFLOW_STACK_IMAGE` names an image
//! with `redis-cli` (`redis:7-alpine`), in a throwaway isolated container.

use std::process::Command;

use devflow_engine::stack;

fn image() -> Option<String> {
    std::env::var("DEVFLOW_STACK_IMAGE")
        .ok()
        .filter(|image| !image.is_empty())
}

fn docker() -> std::path::PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|dir| dir.join("docker"))
        .find(|at| at.is_file())
        .expect("docker on PATH")
}

fn said(args: &[&str]) -> (bool, String) {
    let out = Command::new(docker()).args(args).output().expect("docker");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).trim().to_owned(),
    )
}

fn project(compose: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("compose.yaml"), compose).expect("compose");
    dir
}

fn gone(name: &str, network: &str) -> bool {
    let (_, left) = said(&[
        "ps",
        "-aq",
        "--filter",
        &format!("label=com.docker.compose.project={name}"),
    ]);
    let (exists, _) = said(&["network", "inspect", network]);
    left.is_empty() && !exists
}

/// The digest the person would confirm for the stack at `root` now.
fn confirmed(root: &std::path::Path) -> String {
    stack::resolved(&docker(), root, "compose.yaml")
        .expect("resolved")
        .1
}

#[test]
fn a_stack_runs_on_an_internal_network_its_exploits_reach_and_is_taken_down() {
    let Some(image) = image() else { return };
    let dir = project(&format!(
        "services:\n  store:\n    image: {image}\n    expose: [\"6379\"]\n"
    ));
    let scratch = dir.path().join("scratch");
    let up = stack::up(
        &docker(),
        dir.path(),
        "compose.yaml",
        &confirmed(dir.path()),
        &scratch,
        "t1",
    )
    .expect("up");
    let network = up.network.clone();
    assert_eq!(up.targets, ["http://store:6379"]);
    assert_eq!(
        said(&["network", "inspect", &network, "--format", "{{.Internal}}"]).1,
        "true"
    );
    let (_, pong) = said(&[
        "run",
        "--rm",
        "--network",
        &network,
        &image,
        "redis-cli",
        "-h",
        "store",
        "ping",
    ]);
    assert_eq!(
        pong, "PONG",
        "an exploit attached to the network reaches the service"
    );
    // No way out: a container on it has no default route.
    let (_, routes) = said(&[
        "run",
        "--rm",
        "--network",
        &network,
        &image,
        "cat",
        "/proc/net/route",
    ]);
    let default = routes
        .lines()
        .skip(1)
        .any(|line| line.split_whitespace().nth(1) == Some("00000000"));
    assert!(
        !default,
        "a public address is not reachable from the stack: {routes}"
    );
    drop(up);
    assert!(
        gone("devflow-stack-t1", &network),
        "taken down with its network"
    );
}

#[test]
fn a_stack_that_fails_to_start_is_taken_down_too() {
    let Some(image) = image() else { return };
    let dir = project(&format!(
        "services:\n  broken:\n    image: {image}\n    command: [\"sh\", \"-c\", \"exit 3\"]\n    restart: \"no\"\n"
    ));
    let refused = stack::up(
        &docker(),
        dir.path(),
        "compose.yaml",
        &confirmed(dir.path()),
        &dir.path().join("scratch"),
        "t2",
    );
    assert!(refused.is_err(), "it never came up");
    assert!(
        gone("devflow-stack-t2", "devflow-stack-t2-net"),
        "nothing of it is left"
    );
}

#[test]
fn a_stack_that_would_leave_its_network_never_starts() {
    let Some(image) = image() else { return };
    let dir = project(&format!(
        "services:\n  open:\n    image: {image}\n    ports: [\"127.0.0.1:16379:6379\"]\n"
    ));
    let Err(refused) = stack::up(
        &docker(),
        dir.path(),
        "compose.yaml",
        &confirmed(dir.path()),
        &dir.path().join("scratch"),
        "t3",
    ) else {
        panic!("refused");
    };
    assert!(refused.contains("`ports`"), "{refused}");
    assert!(gone("devflow-stack-t3", "devflow-stack-t3-net"));
}

fn git(root: &std::path::Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t.test",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .current_dir(root)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// A hypothesis that wants a target runs against the stack: its exploit,
/// attached to the stack's network, reaches the service and comes back
/// confirmed.
#[cfg(unix)]
#[test]
fn an_exploit_that_wants_a_target_runs_against_the_stack() {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, SystemTime};
    let Some(image) = image() else { return };
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().canonicalize().expect("root").join("project");
    std::fs::create_dir_all(root.join("src")).expect("src");
    std::fs::write(
        root.join("compose.yaml"),
        format!("services:\n  store:\n    image: {image}\n    expose: [\"6379\"]\n"),
    )
    .expect("compose");
    std::fs::write(root.join("src/session.rs"), "fn a() {}\n").expect("src");
    git(&root, &["init", "-q"]);
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "first"]);
    let head = git(&root, &["rev-parse", "HEAD"]);
    let config = devflow_engine::config::parse(&format!(
        "version: 1\nstages:\n  attack:\n    run: per-item\n    sandbox: docker\n    image: {image}\n    test: sh \"$DEVFLOW_EXPLOIT\"\n"
    ))
    .expect("config");
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).expect("bin");
    let code = "if redis-cli -h store ping | grep -q PONG; then echo \"FAIL store-reachable: the store answers\"; exit 1; fi\necho \"ok store-reachable\"\n";
    // One exploit says the stack's target it reaches; one says none, and
    // runs with no network at all.
    let answer = serde_json::json!({ "version": 1, "hypotheses": [
        { "id": "h1", "title": "the store answers anyone", "class": "authz", "file": "src/session.rs", "line": 1,
          "severity": "high", "status": "tried", "reason": "no password on the store",
          "exploit": { "path": "tests/store.sh", "test": "store-reachable", "code": code, "target": "http://store:6379" } },
        { "id": "h2", "title": "the store answers from outside", "class": "exposure", "file": "src/session.rs", "line": 1,
          "severity": "high", "status": "tried", "reason": "said no target",
          "exploit": { "path": "tests/outside.sh", "test": "store-reachable", "code": code } },
    ] });
    let envelope = serde_json::json!({ "type": "result", "result": answer.to_string(), "total_cost_usd": 0.1 });
    std::fs::write(bin.join("answer.json"), envelope.to_string()).expect("answer");
    let script = bin.join("claude");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\ncat > /dev/null\ncat '{}/answer.json'\n",
            bin.display()
        ),
    )
    .expect("script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("mode");
    let up = stack::up(
        &docker(),
        &root,
        "compose.yaml",
        &confirmed(&root),
        &dir.path().join("stacks"),
        "t4",
    )
    .expect("up");
    let runs = devflow_engine::runs::Runs {
        dialect: &devflow_engine::Dialect::DEVFLOW,
        home: dir.path().join("home"),
        checkout: root.clone(),
    };
    let reach = move |_: devflow_engine::config::Agent| -> Result<String, String> {
        Ok(script.display().to_string())
    };
    let redact = |text: &str| text.to_owned();
    let files = vec!["src/session.rs".to_owned()];
    let done = devflow_engine::attack::attacked(&devflow_engine::attack::Given {
        root: &root,
        runs: &runs,
        config: &config,
        card: devflow_engine::evidence::Card {
            id: "card_1",
            title: "Store",
            body: "",
        },
        git: devflow_engine::review::Git {
            base: &head,
            head: &head,
            files: &files,
            diff: "+fn a() {}\n",
        },
        brief: None,
        evidence: None,
        review: None,
        env: &[],
        at: SystemTime::now(),
        budget: Duration::from_secs(120),
        reach: &reach,
        redact: &redact,
        personas: devflow_engine::review::Personas::default(),
        retro: false,
        scratch: Some(&dir.path().join("trees")),
        flow: None,
        stack: Some(&up),
    })
    .expect("attacked");
    let one = &done.report["hypotheses"][0];
    assert_eq!(one["status"], "confirmed", "{one:#}");
    assert_eq!(one["verified"]["stack"], true);
    let alone = &done.report["hypotheses"][1];
    assert_eq!(
        alone["status"], "refuted",
        "no target said, no network: {alone:#}"
    );
    assert!(alone["verified"]["stack"].is_null());
    // Its proof runs against the stack too, at HEAD only: the stack runs
    // the checkout as it is now, so its base side is said skipped.
    let proved = devflow_engine::attack::prove(&devflow_engine::attack::Proving {
        root: &root,
        folder: std::path::Path::new(&done.folder),
        config: &config,
        head: &head,
        scratch: &dir.path().join("trees"),
        at: SystemTime::now(),
        stack: Some(&up),
    })
    .expect("proved");
    drop(up);
    let proof = &proved["hypotheses"][0]["proof"];
    assert_eq!(proof["stack"], true, "{proof:#}");
    assert_eq!(proof["base"]["result"], "skipped", "{proof:#}");
    assert_eq!(
        proof["head"]["result"], "red",
        "unfixed, it still reaches the store: {proof:#}"
    );
    assert!(devflow_engine::attack::unproven(&proved["hypotheses"][0])
        .is_some_and(|why| why.contains("still open")));
    assert!(gone("devflow-stack-t4", "devflow-stack-t4-net"));
}

/// What the person confirms is the stack as compose resolves it: a change
/// to a file it pulls in changes it, not only a change to the compose file.
#[test]
fn a_change_to_what_the_stack_pulls_in_changes_what_was_confirmed() {
    let Some(image) = image() else { return };
    let dir = project(&format!(
        "services:\n  store:\n    image: {image}\n    environment:\n      - MODE=${{MODE}}\n"
    ));
    std::fs::write(dir.path().join(".env"), "MODE=one\n").expect("env");
    let (_, first) = stack::resolved(&docker(), dir.path(), "compose.yaml").expect("resolved");
    std::fs::write(dir.path().join(".env"), "MODE=two\n").expect("env");
    let (config, second) =
        stack::resolved(&docker(), dir.path(), "compose.yaml").expect("resolved");
    assert_ne!(first, second, "{config}");
}

/// A stack runs only images its person saw: one not on this machine is
/// refused, and a tag moved to another image is another stack.
#[test]
fn a_retagged_or_missing_image_is_another_stack() {
    let Some(image) = image() else { return };
    let tag = "devflow-retag:test";
    let other = std::env::var("DEVFLOW_STACK_OTHER_IMAGE")
        .unwrap_or_else(|_| "postgres:15-alpine".to_owned());
    assert!(said(&["tag", &image, tag]).0, "tag");
    let dir = project(&format!("services:\n  store:\n    image: {tag}\n"));
    let (_, first) = stack::resolved(&docker(), dir.path(), "compose.yaml").expect("resolved");
    assert!(said(&["tag", &other, tag]).0, "retag");
    let (_, second) = stack::resolved(&docker(), dir.path(), "compose.yaml").expect("resolved");
    let _ = said(&["rmi", tag]);
    assert_ne!(first, second, "a moved tag is another stack");
    let missing = project("services:\n  store:\n    image: devflow-absent:none\n");
    let Err(refused) = stack::resolved(&docker(), missing.path(), "compose.yaml") else {
        panic!("absent");
    };
    assert!(refused.contains("not on this machine"), "{refused}");
}
